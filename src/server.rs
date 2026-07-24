//! Hush protocol server.
//!
//! Handles session negotiation, request routing, panic recovery,
//! and media-token management.
//!
//! Mirrors [`hush-go/server`](https://github.com/feralbureau/hush-go/tree/main/server).

use std::collections::HashMap;
use std::future::Future;
use std::net::UdpSocket;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time;

use crate::frame::{self, Response, StatusCode};
use crate::logger::Logger;
use crate::media::{self, TokenStore};
use crate::session::{self, ApiKeyStore, Session, SessionStore, SessionConfig};
use crate::tlv;
use crate::transport;

use x25519_dalek::{PublicKey, StaticSecret};

// ── Request ─────────────────────────────────────────────────

/// A decoded request with session metadata.
/// Mirrors [`hush-go/server.Request`](https://github.com/feralbureau/hush-go/blob/main/server/handler.go).
#[derive(Debug, Clone)]
pub struct Request {
    pub opcode: u16,
    pub payload: tlv::Map, // non-empty; empty map if none was sent
    pub session_id: u64,
    pub api_key_id: String,
}

// ── FrameStream (streaming handler wrapper) ────────────────

/// A bidirectional QUIC stream wrapper for Hush frame I/O.
/// Passed to streaming handlers instead of raw quinn streams.
pub struct FrameStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl FrameStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        FrameStream { send, recv }
    }

    /// Write a response frame.
    pub async fn write_response(&mut self, key: &[u8], seq: u32, resp: &Response) -> Result<(), frame::RequestError> {
        let body = frame::encode_response_body(Some(key), resp)?;
        frame::write_frame_async(&mut self.send, seq, &body).await?;
        Ok(())
    }

    /// Read a request frame.
    pub async fn read_request(&mut self, key: &[u8]) -> Result<(frame::Request, u32), frame::RequestError> {
        frame::read_request_async(&mut self.recv, Some(key)).await
    }
}

// ── Handler dispatch types ─────────────────────────────────

/// Mirrors `hush-go/server.HandlerFunc` — receives a Request and returns a Response.
type SyncHandler = Arc<dyn Fn(Request) -> Result<Response, String> + Send + Sync>;

/// Mirrors `hush-go/server.StreamHandlerFunc` — receives Request + stream + key.
type StreamHandler = Arc<dyn Fn(Request, FrameStream, Vec<u8>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

enum HandlerType {
    Sync(SyncHandler),
    Stream(StreamHandler),
}

// ── Server ──────────────────────────────────────────────────

/// A Hush protocol server.
pub struct Server {
    handlers: Arc<Mutex<HashMap<u16, HandlerType>>>,
    key_store: Arc<dyn ApiKeyStore>,
    sessions: Arc<SessionStore>,
    next_id: AtomicU64,
    server_priv: StaticSecret,
    server_pub: PublicKey,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    media_store: Option<Arc<Mutex<TokenStore>>>,
    logger: Option<Arc<Logger>>,
    session_cfg: SessionConfig,
}

impl Server {
    /// Create a new server.
    pub fn new(key_store: impl ApiKeyStore + 'static) -> Self {
        let server_priv = session::generate_static_key();
        let server_pub = PublicKey::from(&server_priv);
        let cfg = SessionConfig::default().fill();

        Server {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            key_store: Arc::new(key_store),
            sessions: Arc::new(SessionStore::new(cfg.clone())),
            next_id: AtomicU64::new(1),
            server_priv,
            server_pub,
            tls_config: None,
            media_store: None,
            logger: None,
            session_cfg: cfg,
        }
    }

    // ── Builder methods ────────────────────────────────────

    pub fn with_tls(mut self, tls: rustls::ServerConfig) -> Self {
        self.tls_config = Some(Arc::new(tls));
        self
    }

    pub fn with_media(mut self, _base_url: &str) -> Self {
        let sessions = self.sessions.clone();
        let store = TokenStore::with_validator(move |sid| sessions.get(sid).is_some());
        self.media_store = Some(Arc::new(Mutex::new(store)));
        self
    }

    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = Some(Arc::new(logger));
        self
    }

    pub fn with_session_config(mut self, cfg: SessionConfig) -> Self {
        self.session_cfg = cfg.fill();
        self.sessions = Arc::new(SessionStore::new(self.session_cfg.clone()));
        self
    }

    // ── Handler registration ───────────────────────────────

    /// Register a request-response handler.
    /// Mirrors [`hush-go/server.HandleFunc`](https://github.com/feralbureau/hush-go/blob/main/server/server.go).
    pub fn handle<F>(&self, opcode: u16, handler: F)
    where
        F: Fn(Request) -> Result<Response, String> + Send + Sync + 'static,
    {
        self.handlers
            .lock()
            .unwrap()
            .insert(opcode, HandlerType::Sync(Arc::new(handler)));
    }

    /// Register a streaming handler.
    /// Mirrors [`hush-go/server.HandleStreamFunc`](https://github.com/feralbureau/hush-go/blob/main/server/server.go).
    pub fn handle_stream<F, Fut>(&self, opcode: u16, handler: F)
    where
        F: Fn(Request, FrameStream, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let wrapped: StreamHandler = Arc::new(move |req, stream, key| Box::pin(handler(req, stream, key)));
        self.handlers
            .lock()
            .unwrap()
            .insert(opcode, HandlerType::Stream(wrapped));
    }

    // ── TLS helper ─────────────────────────────────────────

    /// Load a TLS server config from PEM files.
    pub fn load_tls(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig, ServerError> {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| ServerError::Config(format!("read cert: {e}")))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| ServerError::Config(format!("read key: {e}")))?;

        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Config(format!("parse cert: {e}")))?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| ServerError::Config(format!("parse key: {e}")))?
            .ok_or_else(|| ServerError::Config("no private key".into()))?;

        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Config(format!("tls: {e}")))
    }

    // ── Listen ─────────────────────────────────────────────

    /// Bind to addr and serve. Convenience wrapper around [`listen_on`].
    pub async fn listen_and_serve(&self, addr: &str) -> Result<(), ServerError> {
        let tls = self.tls_config
            .as_ref()
            .ok_or_else(|| ServerError::Config("TLS config required; use with_tls()".into()))?
            .as_ref()
            .clone();

        let endpoint = transport::bind(addr, tls)?;
        self.listen_on(endpoint).await
    }

    /// Serve on an existing raw UDP socket.
    /// Mirrors [`hush-go/server.ListenAndServeOnConn`](https://github.com/feralbureau/hush-go/blob/main/server/server.go).
    pub async fn listen_on_conn(&self, conn: UdpSocket) -> Result<(), ServerError> {
        let tls = self.tls_config
            .as_ref()
            .ok_or_else(|| ServerError::Config("TLS config required; use with_tls()".into()))?
            .as_ref()
            .clone();

        let mut tls_clone = tls.clone();
        tls_clone.alpn_protocols = vec![transport::DEFAULT_ALPN.as_bytes().to_vec()];

        let quic_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_clone)
                .map_err(|e| ServerError::Config(format!("quic config: {e}")))?,
        ));

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quinn::ServerConfig::clone(&quic_config)),
            conn,
            Arc::new(quinn::TokioRuntime),
        ).map_err(|e| ServerError::Config(format!("endpoint: {e}")))?;

        self.listen_on(endpoint).await
    }

    /// Serve on an existing QUIC endpoint.
    pub async fn listen_on(&self, endpoint: quinn::Endpoint) -> Result<(), ServerError> {
        let addr = endpoint.local_addr()
            .map_err(|e| ServerError::Config(format!("local addr: {e}")))?;

        self.log("INF", format_args!("listening on {addr} (ALPN: {})", transport::DEFAULT_ALPN));

        // Start session GC
        let sessions = self.sessions.clone();
        let gc_interval = self.session_cfg.gc_interval;
        tokio::spawn(async move {
            gc_loop(sessions, gc_interval).await;
        });

        // Accept loop
        loop {
            let conn = match endpoint.accept().await {
                Some(conn) => match conn.await {
                    Ok(c) => c,
                    Err(e) => {
                        self.log("WRN", format_args!("accept: {e}"));
                        continue;
                    }
                },
                None => return Err(ServerError::Config("endpoint closed".into())),
            };

            let handlers = self.handlers.clone();
            let key_store = self.key_store.clone();
            let sessions = self.sessions.clone();
            let server_priv = self.server_priv.clone();
            let server_pub = self.server_pub;
            let logger = self.logger.clone();
            let sid = self.next_id.fetch_add(1, Ordering::SeqCst);

            tokio::spawn(async move {
                let _ = handle_connection(
                    conn, sid, handlers, key_store, sessions,
                    server_priv, server_pub, logger,
                ).await;
            });
        }
    }

    // ── Accessors ──────────────────────────────────────────

    pub fn session_store(&self) -> Arc<SessionStore> {
        self.sessions.clone()
    }

    pub fn media_store(&self) -> Option<Arc<Mutex<TokenStore>>> {
        self.media_store.clone()
    }

    /// Issue a media token bound to a session.
    /// Mirrors hush-go/server.IssueMediaToken.
    pub fn issue_media_token(&self, session_id: u64, track_id: &str) -> Result<media::Token, ServerError> {
        let store = self.media_store
            .as_ref()
            .ok_or_else(|| ServerError::Config("media support not enabled".into()))?;
        let guard = store.lock().unwrap();
        Ok(guard.issue(session_id, track_id))
    }

    // ── Internal ───────────────────────────────────────────

    fn log(&self, level: &str, msg: std::fmt::Arguments<'_>) {
        if let Some(ref l) = self.logger {
            match level {
                "INF" => l.info(msg),
                "WRN" => l.warn(msg),
                "ERR" => l.error(msg),
                _ => l.info(msg),
            }
        }
    }
}

// ── Response helpers ────────────────────────────────────────

/// Create a successful response with a payload.
/// Mirrors [`hush-go/server.NewResponse`](https://github.com/feralbureau/hush-go/blob/main/server/handler.go).
pub fn new_response(payload: tlv::Map) -> Response {
    Response { status: StatusCode::Success, payload: Some(payload), seq: 0 }
}

/// Create an error response with a message.
/// Mirrors [`hush-go/server.ErrorResponse`](https://github.com/feralbureau/hush-go/blob/main/server/handler.go).
pub fn error_response(code: StatusCode, message: &str) -> Response {
    let mut m = tlv::Map::new();
    m.set("error", tlv::Value::String(message.into()));
    Response { status: code, payload: Some(m), seq: 0 }
}

// ── Connection handler ─────────────────────────────────────

async fn handle_connection(
    conn: quinn::Connection,
    session_id: u64,
    handlers: Arc<Mutex<HashMap<u16, HandlerType>>>,
    key_store: Arc<dyn ApiKeyStore>,
    sessions: Arc<SessionStore>,
    server_priv: StaticSecret,
    server_pub: PublicKey,
    logger: Option<Arc<Logger>>,
) -> Result<(), ServerError> {
    let (mut send, mut recv) = conn.accept_bi().await?;

    // ── Handshake ──────────────────────────────────────────
    let api_key_id = {
        let mut header = [0u8; 2];
        recv.read_exact(&mut header).await?;
        let key_len = u16::from_be_bytes(header) as usize;
        if key_len == 0 || key_len > 256 {
            return Err(ServerError::Config("invalid key length".into()));
        }

        let mut key_buf = vec![0u8; key_len + 32];
        recv.read_exact(&mut key_buf).await?;

        let aid = String::from_utf8_lossy(&key_buf[..key_len]).to_string();
        let client_pub_bytes: [u8; 32] = key_buf[key_len..]
            .try_into()
            .map_err(|_| ServerError::Config("invalid client pubkey".into()))?;
        let client_pub = PublicKey::from(client_pub_bytes);

        let api_key_secret = key_store.get(&aid)
            .ok_or_else(|| ServerError::Config(format!("unknown api key '{aid}'")))?;

        let shared = session::shared_secret_static(&server_priv, &client_pub);
        let session_key = session::derive_session_key(shared.as_bytes(), &api_key_secret)?;

        let spub_bytes = server_pub.to_bytes();
        let mut resp = Vec::with_capacity(40);
        resp.extend_from_slice(&spub_bytes);
        resp.extend_from_slice(&session_id.to_be_bytes());
        send.write_all(&resp).await?;

        let sess = Session::new(session_id, aid.clone(), session_key);
        sessions.insert(sess);

        log_info(&logger, format_args!(
            "session[{session_id}] established key={aid} remote={}", conn.remote_address()
        ));

        aid
    };

    // ── Accept request streams ─────────────────────────────
    loop {
        let (req_send, req_recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };

        let handlers = handlers.clone();
        let sessions = sessions.clone();
        let logger = logger.clone();
        let aid = api_key_id.clone();

        tokio::spawn(async move {
            handle_request_stream(
                req_send, req_recv, session_id, aid, handlers, sessions, logger,
            ).await;
        });
    }

    sessions.delete(session_id);
    log_info(&logger, format_args!("session[{session_id}] closed"));
    Ok(())
}

// ── Per-stream dispatch ────────────────────────────────────

async fn handle_request_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session_id: u64,
    api_key_id: String,
    handlers: Arc<Mutex<HashMap<u16, HandlerType>>>,
    sessions: Arc<SessionStore>,
    logger: Option<Arc<Logger>>,
) {
    let log = |level: &str, msg: std::fmt::Arguments| match level {
        "INF" => log_info(&logger, msg),
        "WRN" => log_warn(&logger, msg),
        "ERR" => log_err(&logger, msg),
        _ => log_info(&logger, msg),
    };

    // ── Session expiry check ───────────────────────────────
    if let Some(sess) = sessions.get(session_id) {
        if sessions.is_expired(&sess) || sessions.is_idle_dead(&sess) {
            log("WRN", format_args!("session[{session_id}] expired"));
            let resp = Response { status: StatusCode::SessionExpired, payload: None, seq: 0 };
            if let Ok(body) = frame::encode_response_body(Some(&sess.key), &resp) {
                let _ = frame::write_frame_async(&mut send, 0, &body).await;
            }
            return;
        }
    }
    let session_key = sessions.get(session_id).map(|s| s.key.clone()).unwrap_or_default();
    if let Some(mut sess) = sessions.get(session_id) {
        sess.touch();
    }

    // ── Read request ───────────────────────────────────────
    let (freq, seq) = match frame::read_request_async(&mut recv, Some(&session_key)).await {
        Ok(r) => r,
        Err(e) => {
            log("WRN", format_args!("session[{session_id}] read request: {e}"));
            let resp = error_response(StatusCode::BadRequest, "bad request");
            if let Ok(body) = frame::encode_response_body(Some(&session_key), &resp) {
                let _ = frame::write_frame_async(&mut send, 0, &body).await;
            }
            return;
        }
    };

    // ── Look up handler ────────────────────────────────────
    let handler = {
        let guard = handlers.lock().unwrap();
        guard.get(&freq.opcode).cloned()
    };

    let handler = match handler {
        Some(h) => h,
        None => {
            log("WRN", format_args!("session[{session_id}] opcode=0x{:04x} not found", freq.opcode));
            let mut m = tlv::Map::new();
            m.set("opcode", tlv::Value::Uint16(freq.opcode));
            let resp = Response { status: StatusCode::NotFound, payload: Some(m), seq };
            if let Ok(body) = frame::encode_response_body(Some(&session_key), &resp) {
                let _ = frame::write_frame_async(&mut send, seq, &body).await;
            }
            return;
        }
    };

    let req = Request {
        opcode: freq.opcode,
        payload: freq.payload.unwrap_or_else(tlv::Map::new),
        session_id,
        api_key_id,
    };

    match handler {
        HandlerType::Stream(stream_handler) => {
            log("INF", format_args!(
                "session[{}] opcode=0x{:04x} stream start", req.session_id, req.opcode
            ));
            let stream = FrameStream::new(send, recv);
            stream_handler(req, stream, session_key).await;
        }
        HandlerType::Sync(handler) => {
            let start = Instant::now();
            match handler(req) {
                Ok(resp) => {
                    let elapsed = start.elapsed();
                    log("INF", format_args!(
                        "session[{}] opcode=0x{:04x} status={} elapsed={}s",
                        session_id, freq.opcode, resp.status.name(), elapsed.as_secs_f64(),
                    ));
                    if let Ok(body) = frame::encode_response_body(Some(&session_key), &resp) {
                        let _ = frame::write_frame_async(&mut send, seq, &body).await;
                    }
                }
                Err(e) => {
                    log("ERR", format_args!(
                        "session[{session_id}] opcode=0x{:04x} error: {e}", freq.opcode
                    ));
                    let resp = error_response(StatusCode::InternalError, "internal error");
                    if let Ok(body) = frame::encode_response_body(Some(&session_key), &resp) {
                        let _ = frame::write_frame_async(&mut send, seq, &body).await;
                    }
                }
            }
        }
    }
}

// ── GC loop ────────────────────────────────────────────────

async fn gc_loop(sessions: Arc<SessionStore>, interval: Duration) {
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        sessions.gc();
    }
}

// ── Logger shortcuts ───────────────────────────────────────

fn log_info(logger: &Option<Arc<Logger>>, msg: std::fmt::Arguments<'_>) {
    if let Some(ref l) = logger { l.info(msg); }
}

fn log_warn(logger: &Option<Arc<Logger>>, msg: std::fmt::Arguments<'_>) {
    if let Some(ref l) = logger { l.warn(msg); }
}

fn log_err(logger: &Option<Arc<Logger>>, msg: std::fmt::Arguments<'_>) {
    if let Some(ref l) = logger { l.error(msg); }
}

// ── Errors ──────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("server: {0}")]
    Config(String),
    #[error("server: session: {0}")]
    Session(#[from] session::SessionError),
    #[error("server: io: {0}")]
    Io(#[from] std::io::Error),
    #[error("server: quinn: {0}")]
    Quinn(#[from] quinn::ConnectionError),
    #[error("server: transport: {0}")]
    Transport(#[from] transport::TransportError),
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

// Allow HandlerType to be cloned
impl Clone for HandlerType {
    fn clone(&self) -> Self {
        match self {
            HandlerType::Sync(h) => HandlerType::Sync(h.clone()),
            HandlerType::Stream(h) => HandlerType::Stream(h.clone()),
        }
    }
}
