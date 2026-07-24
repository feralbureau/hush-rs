use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::frame::{self, Response, StatusCode};
use crate::session::{self, ApiKeyStore, Session};
use crate::tlv;
use crate::transport;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("server: {0}")]
    Config(String),
    #[error("server: session: {0}")]
    Session(#[from] session::SessionError),
    #[error("server: frame: {0}")]
    Io(#[from] std::io::Error),
    #[error("server: quinn: {0}")]
    Quinn(#[from] quinn::ConnectionError),
}

impl From<quinn::WriteError> for ServerError {
    fn from(e: quinn::WriteError) -> Self {
        ServerError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }
}

impl From<quinn::ReadExactError> for ServerError {
    fn from(e: quinn::ReadExactError) -> Self {
        ServerError::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))
    }
}

type SyncHandler = Arc<dyn Send + Sync + Fn(tlv::Map) -> Result<Response, String>>;

enum Handler {
    Sync(SyncHandler),
}

pub struct Server {
    handlers: Arc<Mutex<HashMap<u16, Handler>>>,
    key_store: Arc<dyn ApiKeyStore>,
}

impl Server {
    pub fn new(key_store: impl ApiKeyStore + 'static) -> Self {
        Server {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            key_store: Arc::new(key_store),
        }
    }

    pub fn handle<F>(&self, opcode: u16, handler: F)
    where
        F: Fn(tlv::Map) -> Result<Response, String> + Send + Sync + 'static,
    {
        self.handlers
            .lock()
            .unwrap()
            .insert(opcode, Handler::Sync(Arc::new(handler)));
    }

    /// Load TLS config from cert and key PEM files.
    pub fn load_tls(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig, ServerError> {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| ServerError::Config(format!("read cert: {}", e)))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| ServerError::Config(format!("read key: {}", e)))?;

        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Config(format!("parse cert: {}", e)))?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| ServerError::Config(format!("parse key: {}", e)))?
            .ok_or_else(|| ServerError::Config("no private key".into()))?;

        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Config(format!("tls: {}", e)))
    }

    /// Accept connections on a pre-bound QUIC endpoint.
    pub async fn listen_on(&self, endpoint: quinn::Endpoint) -> Result<(), ServerError> {
        let addr = endpoint.local_addr().map_err(|e| ServerError::Config(format!("local addr: {}", e)))?;
        log::info!("hush: listening on {} (ALPN: {})", addr, transport::DEFAULT_ALPN);

        let handlers = self.handlers.clone();
        let key_store = self.key_store.clone();

        loop {
            let conn = match endpoint.accept().await {
                Some(conn) => conn.await?,
                None => return Err(ServerError::Config("endpoint closed".into())),
            };

            let handlers = handlers.clone();
            let key_store = key_store.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, handlers, key_store).await {
                    log::error!("{}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    conn: quinn::Connection,
    handlers: Arc<Mutex<HashMap<u16, Handler>>>,
    key_store: Arc<dyn ApiKeyStore>,
) -> Result<(), ServerError> {
    let (mut send, mut recv) = conn.accept_bi().await?;

    let (server_priv, server_pub_key) = session::generate_key_pair();

    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;
    let key_len = u16::from_be_bytes(header) as usize;
    if key_len == 0 || key_len > 256 {
        return Err(ServerError::Config("invalid key length".into()));
    }

    let mut key_buf = vec![0u8; key_len + 32];
    recv.read_exact(&mut key_buf).await?;

    let api_key_id = String::from_utf8_lossy(&key_buf[..key_len]).to_string();
    let client_pub_bytes: [u8; 32] = key_buf[key_len..]
        .try_into()
        .map_err(|_| ServerError::Config("invalid client pubkey".into()))?;
    let client_pub = x25519_dalek::PublicKey::from(client_pub_bytes);

    let api_key_secret = key_store
        .get(&api_key_id)
        .ok_or_else(|| ServerError::Config(format!("unknown key: {}", api_key_id)))?;

    let spub_bytes = server_pub_key.to_bytes();
    let session_id: u64 = 1;

    let shared = session::shared_secret(server_priv, &client_pub);
    let session_key = session::derive_session_key(shared.as_bytes(), &api_key_secret)?;

    let mut resp = Vec::with_capacity(40);
    resp.extend_from_slice(&spub_bytes);
    resp.extend_from_slice(&session_id.to_be_bytes());
    send.write_all(&resp).await?;

    let sess = Session::new(session_id, api_key_id, session_key);
    log::info!("session[{}] established", sess.id);

    loop {
        let (mut req_send, mut req_recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break Ok(()),
        };

        let handlers = handlers.clone();
        let sess = sess.clone();

        tokio::spawn(async move {
            handle_stream(&mut req_recv, &mut req_send, &sess, &handlers).await;
        });
    }
}

async fn handle_stream(
    recv: &mut (impl AsyncReadExt + Unpin),
    send: &mut (impl AsyncWriteExt + Unpin),
    sess: &Session,
    handlers: &Mutex<HashMap<u16, Handler>>,
) {
    let mut len_buf = [0u8; 4];
    if recv.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let frame_len = u32::from_be_bytes(len_buf);
    if frame_len > frame::MAX_FRAME_SIZE {
        return;
    }

    let mut payload = vec![0u8; frame_len as usize];
    if recv.read_exact(&mut payload).await.is_err() {
        return;
    }

    let (req, seq) = match frame::decode_request(Some(&sess.key), &payload) {
        Ok(r) => r,
        Err(_) => return,
    };

    let response = {
        let guarded = handlers.lock().unwrap();
        match guarded.get(&req.opcode) {
            Some(Handler::Sync(f)) => {
                let payload = req.payload.unwrap_or_else(tlv::Map::new);
                match f(payload) {
                    Ok(r) => r,
                    Err(e) => Response {
                        status: StatusCode::InternalError,
                        payload: Some({
                            let mut m = tlv::Map::new();
                            m.set("error", tlv::Value::String(e));
                            m
                        }),
                        seq,
                    },
                }
            }
            None => Response {
                status: StatusCode::NotFound,
                payload: Some({
                    let mut m = tlv::Map::new();
                    m.set("opcode", tlv::Value::Uint16(req.opcode));
                    m
                }),
                seq,
            },
        }
    };

    if let Ok(resp_body) = frame::encode_response_body(Some(&sess.key), &response) {
        if let Ok(frame_bytes) = frame::encode_frame(seq, &resp_body) {
            let _ = send.write_all(&frame_bytes).await;
        }
    }
}
