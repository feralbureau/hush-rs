use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::frame::{self, Response, StatusCode};
use crate::session::{self, ApiKeyStore, Session, SessionStore};
use crate::tlv;

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


pub struct Server {
    _sessions: Arc<SessionStore>,
    key_store: Arc<dyn ApiKeyStore>,
    server_public: x25519_dalek::PublicKey,
}

impl Server {
    pub fn new(key_store: impl ApiKeyStore + 'static) -> Self {
        let (_secret, public) = session::generate_key_pair();
        Server {
            _sessions: Arc::new(SessionStore::default()),
            key_store: Arc::new(key_store),
            server_public: public,
        }
    }

    pub async fn listen(&self, addr: &str) -> Result<(), ServerError> {
        let cert_pem = std::fs::read("test-cert.pem")
            .map_err(|e| ServerError::Config(format!("read cert: {}", e)))?;
        let key_pem = std::fs::read("test-key.pem")
            .map_err(|e| ServerError::Config(format!("read key: {}", e)))?;

        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Config(format!("parse cert: {}", e)))?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| ServerError::Config(format!("parse key: {}", e)))?
            .ok_or_else(|| ServerError::Config("no private key".into()))?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Config(format!("tls: {}", e)))?;

        let endpoint = crate::transport::listen(addr, tls_config)
            .map_err(|e| ServerError::Config(format!("listen: {}", e)))?;

        log::info!("hush: listening on {} (ALPN: {})", addr, crate::transport::DEFAULT_ALPN);

        loop {
            let conn = match endpoint.accept().await {
                Some(conn) => conn.await?,
                None => return Err(ServerError::Config("endpoint closed".into())),
            };

            let key_store = self.key_store.clone();
            let server_pub = self.server_public;

            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, key_store, server_pub).await {
                    log::error!("{}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    conn: quinn::Connection,
    key_store: Arc<dyn ApiKeyStore>,
    server_pub: x25519_dalek::PublicKey,
) -> Result<(), ServerError> {
    let (mut send, mut recv) = conn.accept_bi().await?;

    let (secret, _) = session::generate_key_pair();

    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;
    let key_len = u16::from_be_bytes(header) as usize;
    if key_len == 0 || key_len > 256 {
        return Err(ServerError::Config("invalid key length".into()));
    }

    let mut key_buf = vec![0u8; key_len + 32];
    recv.read_exact(&mut key_buf).await?;

    let api_key_id = String::from_utf8_lossy(&key_buf[..key_len]).to_string();
    let client_pub_bytes: [u8; 32] = key_buf[key_len..].try_into()
        .map_err(|_| ServerError::Config("invalid client pubkey".into()))?;
    let client_pub = x25519_dalek::PublicKey::from(client_pub_bytes);

    let api_key_secret = key_store.get(&api_key_id)
        .ok_or_else(|| ServerError::Config(format!("unknown key: {}", api_key_id)))?;

    let server_pub_bytes = server_pub.to_bytes();
    let session_id: u64 = 1;

    let shared = session::shared_secret(secret, &client_pub);
    let session_key = session::derive_session_key(shared.as_bytes(), &api_key_secret)?;

    let mut resp = Vec::with_capacity(40);
    resp.extend_from_slice(&server_pub_bytes);
    resp.extend_from_slice(&session_id.to_be_bytes());
    send.write_all(&resp).await?;

    let sess = Session::new(session_id, api_key_id, session_key);
    log::info!("session[{}] established", sess.id);

    loop {
        let (mut req_send, mut req_recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break Ok(()),
        };

        let sess = sess.clone();
        tokio::spawn(async move {
            handle_request(&mut req_recv, &mut req_send, &sess).await;
        });
    }
}

async fn handle_request(
    recv: &mut (impl AsyncReadExt + Unpin),
    send: &mut (impl AsyncWriteExt + Unpin),
    sess: &Session,
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

    // payload = [4-byte seq][encrypted body]
    let (req, seq) = match frame::decode_request(Some(&sess.key), &payload) {
        Ok(r) => r,
        Err(_) => return,
    };

    let response = Response {
        status: StatusCode::NotFound,
        payload: Some({
            let mut m = tlv::Map::new();
            m.set("opcode", tlv::Value::Uint16(req.opcode));
            m
        }),
        seq,
    };

    if let Ok(resp_body) = frame::encode_response_body(Some(&sess.key), &response) {
        if let Ok(frame_bytes) = frame::encode_frame(seq, &resp_body) {
            let _ = send.write_all(&frame_bytes).await;
        }
    }
}
