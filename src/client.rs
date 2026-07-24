use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::frame::{self, FrameError, Request, RequestError, Response};
use crate::session::{self, ApiKey, Session};
use crate::tlv;
use crate::transport;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("client: {0}")]
    Transport(#[from] transport::TransportError),
    #[error("client: {0}")]
    Session(#[from] session::SessionError),
    #[error("client: {0}")]
    Frame(#[from] FrameError),
    #[error("client: {0}")]
    Request(#[from] RequestError),
    #[error("client: {0}")]
    Quinn(#[from] quinn::ConnectionError),
    #[error("client: negotiate: {0}")]
    Negotiate(String),
    #[error("client: io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<quinn::WriteError> for ClientError {
    fn from(e: quinn::WriteError) -> Self {
        ClientError::Negotiate(format!("write: {}", e))
    }
}

impl From<quinn::ReadExactError> for ClientError {
    fn from(e: quinn::ReadExactError) -> Self {
        ClientError::Negotiate(format!("read: {}", e))
    }
}

/// Internal transport type
enum Transport {
    Quinn(quinn::Connection),
    Tcp(tokio::sync::Mutex<tokio_rustls::TlsStream<tokio::net::TcpStream>>),
}

pub struct Client {
    transport: Transport,
    _session: Session,
    seq: AtomicU32,
    session_key: Vec<u8>,
}

impl Client {
    /// Dial a QUIC Hush connection.
    ///
    /// If `api_key` has an empty ID, performs an anonymous handshake.
    pub async fn dial(
        addr: &str,
        api_key: &ApiKey,
        tls_config: Option<rustls::ClientConfig>,
    ) -> Result<Self, ClientError> {
        let tls = tls_config.unwrap_or_else(transport::insecure_client_tls);
        let (conn, _endpoint) = transport::dial(addr, Some(tls)).await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        let (secret, public) = session::generate_key_pair();
        let pub_bytes = public.to_bytes();

        let (session_key, session_id, api_key_id) = if api_key.id.is_empty() {
            // Anonymous: send key_len=0 + pubkey only
            let mut buf = Vec::with_capacity(2 + 32);
            buf.extend_from_slice(&(0u16).to_be_bytes());
            buf.extend_from_slice(&pub_bytes);
            send.write_all(&buf).await?;

            let mut resp = vec![0u8; 32 + 8];
            recv.read_exact(&mut resp).await
                .map_err(|e| ClientError::Negotiate(format!("read handshake resp: {}", e)))?;

            let server_pub_bytes: [u8; 32] = resp[..32]
                .try_into()
                .map_err(|_| ClientError::Negotiate("invalid server pubkey".into()))?;
            let server_pub = x25519_dalek::PublicKey::from(server_pub_bytes);
            let sid = u64::from_be_bytes(resp[32..].try_into().unwrap());

            let shared = session::shared_secret(secret, &server_pub);
            let key = session::derive_session_key(shared.as_bytes(), b"hush-anonymous")?;
            (key, sid, String::new())
        } else {
            let key_id_bytes = api_key.id.as_bytes();
            let mut buf = Vec::with_capacity(2 + key_id_bytes.len() + 32);
            buf.extend_from_slice(&(key_id_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(key_id_bytes);
            buf.extend_from_slice(&pub_bytes);
            send.write_all(&buf).await?;

            let mut resp = vec![0u8; 32 + 8];
            recv.read_exact(&mut resp).await
                .map_err(|e| ClientError::Negotiate(format!("read handshake resp: {}", e)))?;

            let server_pub_bytes: [u8; 32] = resp[..32]
                .try_into()
                .map_err(|_| ClientError::Negotiate("invalid server pubkey".into()))?;
            let server_pub = x25519_dalek::PublicKey::from(server_pub_bytes);
            let sid = u64::from_be_bytes(resp[32..].try_into().unwrap());

            let shared = session::shared_secret(secret, &server_pub);
            let key = session::derive_session_key(shared.as_bytes(), &api_key.secret)?;
            (key, sid, api_key.id.clone())
        };

        let sess = Session::new(session_id, api_key_id, session_key.clone());
        let _ = send.finish();

        Ok(Client {
            transport: Transport::Quinn(conn),
            _session: sess,
            seq: AtomicU32::new(0),
            session_key,
        })
    }

    /// Dial a TCP Hush connection (TLS-over-TCP, useful behind Cloudflare).
    ///
    /// If `api_key` has an empty ID, performs an anonymous handshake.
    pub async fn dial_tcp(
        addr: &str,
        api_key: &ApiKey,
        tls_config: Option<rustls::ClientConfig>,
    ) -> Result<Self, ClientError> {
        let tls = tls_config.unwrap_or_else(transport::insecure_client_tls);
        let mut stream = transport::tcp_dial(addr, tls).await?;

        let (secret, public) = session::generate_key_pair();
        let pub_bytes = public.to_bytes();

        let (session_key, session_id, api_key_id) = if api_key.id.is_empty() {
            // Anonymous
            let mut buf = Vec::with_capacity(2 + 32);
            buf.extend_from_slice(&(0u16).to_be_bytes());
            buf.extend_from_slice(&pub_bytes);
            stream.write_all(&buf).await?;

            let mut resp = vec![0u8; 32 + 8];
            stream.read_exact(&mut resp).await
                .map_err(|e| ClientError::Negotiate(format!("read tcp handshake: {}", e)))?;

            let server_pub_bytes: [u8; 32] = resp[..32]
                .try_into()
                .map_err(|_| ClientError::Negotiate("invalid server pubkey".into()))?;
            let server_pub = x25519_dalek::PublicKey::from(server_pub_bytes);
            let sid = u64::from_be_bytes(resp[32..].try_into().unwrap());

            let shared = session::shared_secret(secret, &server_pub);
            let key = session::derive_session_key(shared.as_bytes(), b"hush-anonymous")?;
            (key, sid, String::new())
        } else {
            let key_id_bytes = api_key.id.as_bytes();
            let mut buf = Vec::with_capacity(2 + key_id_bytes.len() + 32);
            buf.extend_from_slice(&(key_id_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(key_id_bytes);
            buf.extend_from_slice(&pub_bytes);
            stream.write_all(&buf).await?;

            let mut resp = vec![0u8; 32 + 8];
            stream.read_exact(&mut resp).await
                .map_err(|e| ClientError::Negotiate(format!("read tcp handshake: {}", e)))?;

            let server_pub_bytes: [u8; 32] = resp[..32]
                .try_into()
                .map_err(|_| ClientError::Negotiate("invalid server pubkey".into()))?;
            let server_pub = x25519_dalek::PublicKey::from(server_pub_bytes);
            let sid = u64::from_be_bytes(resp[32..].try_into().unwrap());

            let shared = session::shared_secret(secret, &server_pub);
            let key = session::derive_session_key(shared.as_bytes(), &api_key.secret)?;
            (key, sid, api_key.id.clone())
        };

        let sess = Session::new(session_id, api_key_id, session_key.clone());

        Ok(Client {
            transport: Transport::Tcp(tokio::sync::Mutex::new(stream)),
            _session: sess,
            seq: AtomicU32::new(0),
            session_key,
        })
    }

    /// Send a request and receive a response.
    ///
    /// Works for both QUIC and TCP transports.
    pub async fn do_(&self, opcode: u16, payload: Option<tlv::Map>) -> Result<Response, ClientError> {
        match &self.transport {
            Transport::Quinn(conn) => self.do_quinn(conn, opcode, payload).await,
            Transport::Tcp(mtx) => self.do_tcp(mtx, opcode, payload).await,
        }
    }

    async fn do_quinn(
        &self,
        conn: &quinn::Connection,
        opcode: u16,
        payload: Option<tlv::Map>,
    ) -> Result<Response, ClientError> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let (mut send, mut recv) = conn.open_bi().await?;

        let req = Request { opcode, payload };
        let req_body = frame::encode_request_body(Some(&self.session_key), &req)?;
        let frame_bytes = frame::encode_frame(seq, &req_body)?;

        send.write_all(&frame_bytes).await?;

        // Read response: [4-byte len][4-byte seq][data]
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;
        let frame_len = u32::from_be_bytes(len_buf);

        if frame_len > frame::MAX_FRAME_SIZE {
            return Err(ClientError::Frame(FrameError::TooLarge(frame_len, frame::MAX_FRAME_SIZE)));
        }

        let mut rest = vec![0u8; frame_len as usize];
        recv.read_exact(&mut rest).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;

        let resp = frame::decode_response(Some(&self.session_key), &rest)?;
        Ok(resp)
    }

    async fn do_tcp(
        &self,
        mtx: &tokio::sync::Mutex<tokio_rustls::TlsStream<tokio::net::TcpStream>>,
        opcode: u16,
        payload: Option<tlv::Map>,
    ) -> Result<Response, ClientError> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);

        let req = Request { opcode, payload };
        let req_body = frame::encode_request_body(Some(&self.session_key), &req)?;
        let frame_bytes = frame::encode_frame(seq, &req_body)?;

        let mut stream = mtx.lock().await;

        stream.write_all(&frame_bytes).await?;

        // Read response: [4-byte len][4-byte seq][data]
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;
        let frame_len = u32::from_be_bytes(len_buf);

        if frame_len > frame::MAX_FRAME_SIZE {
            return Err(ClientError::Frame(FrameError::TooLarge(frame_len, frame::MAX_FRAME_SIZE)));
        }

        let mut rest = vec![0u8; frame_len as usize];
        stream.read_exact(&mut rest).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;

        let resp = frame::decode_response(Some(&self.session_key), &rest)?;
        Ok(resp)
    }

    pub fn session_id(&self) -> u64 {
        self._session.id
    }
}
