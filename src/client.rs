use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;

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

pub struct Client {
    conn: quinn::Connection,
    _session: Session,
    seq: AtomicU32,
    session_key: Vec<u8>,
}

impl Client {
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

        let session_id = u64::from_be_bytes(resp[32..].try_into().unwrap());

        let shared = session::shared_secret(secret, &server_pub);
        let session_key = session::derive_session_key(shared.as_bytes(), &api_key.secret)?;

        let sess = Session::new(session_id, api_key.id.clone(), session_key.clone());
        let _ = send.finish();

        Ok(Client { conn, _session: sess, seq: AtomicU32::new(0), session_key })
    }

    pub async fn do_(&self, opcode: u16, payload: Option<tlv::Map>) -> Result<Response, ClientError> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let (mut send, mut recv) = self.conn.open_bi().await?;

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

        // Strip the 4-byte length prefix before passing to decode_response
        let resp = frame::decode_response(Some(&self.session_key), &rest)?;
        Ok(resp)
    }

    pub fn session_id(&self) -> u64 {
        self._session.id
    }
}
