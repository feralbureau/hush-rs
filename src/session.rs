use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use thiserror::Error;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const PUB_KEY_SIZE: usize = 32;

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(86400);
const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("hkdf: {0}")]
    Hkdf(&'static str),
    #[error("aes: {0}")]
    Aes(&'static str),
    #[error("{0}")]
    Crypto(String),
}

#[derive(Debug)]
pub struct ApiKey {
    pub id: String,
    pub secret: Vec<u8>,
}

impl ApiKey {
    pub fn generate() -> Self {
        let mut secret = vec![0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let mut id_bytes = vec![0u8; 8];
        OsRng.fill_bytes(&mut id_bytes);
        ApiKey { id: hex::encode(&id_bytes), secret }
    }
}

use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

/// Generate X25519 key pair.
pub fn generate_key_pair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Compute ECDH shared secret. Takes ownership of ephemeral secret.
pub fn shared_secret(priv_key: EphemeralSecret, pub_key: &PublicKey) -> SharedSecret {
    priv_key.diffie_hellman(pub_key)
}

/// Derive AES-256 session key via HKDF-SHA256.
pub fn derive_session_key(shared_secret: &[u8], api_key_secret: &[u8]) -> Result<Vec<u8>, SessionError> {
    let hk = Hkdf::<Sha256>::new(Some(shared_secret), api_key_secret);
    let mut okm = vec![0u8; KEY_SIZE];
    hk.expand(b"hush-v1-key", &mut okm)
        .map_err(|_| SessionError::Hkdf("hkdf expand failed"))?;
    Ok(okm)
}

/// Encrypt plaintext with AES-256-GCM. Returns nonce || ciphertext.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| SessionError::Aes("invalid key length"))?;

    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SessionError::Crypto(format!("aes-gcm encrypt: {}", e)))?;

    let mut out = nonce_bytes;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by encrypt().
pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, SessionError> {
    if data.len() < NONCE_SIZE + TAG_SIZE {
        return Err(SessionError::Crypto("ciphertext too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| SessionError::Aes("invalid key length"))?;

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SessionError::Crypto("gcm decrypt: message authentication failed".into()))
}

// ── Session ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    pub api_key_id: String,
    pub key: Vec<u8>,
    pub created_at: Instant,
    pub last_used: Instant,
}

impl Session {
    pub fn new(id: u64, api_key_id: String, key: Vec<u8>) -> Self {
        let now = Instant::now();
        Session { id, api_key_id, key, created_at: now, last_used: now }
    }

    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

#[derive(Debug)]
pub struct SessionConfig {
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub gc_interval: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_lifetime: DEFAULT_MAX_LIFETIME,
            gc_interval: DEFAULT_GC_INTERVAL,
        }
    }
}

pub trait ApiKeyStore: Send + Sync {
    fn get(&self, id: &str) -> Option<Vec<u8>>;
}

pub struct MapKeyStore {
    keys: HashMap<String, Vec<u8>>,
}

impl MapKeyStore {
    pub fn new() -> Self {
        MapKeyStore { keys: HashMap::new() }
    }

    pub fn insert(&mut self, id: String, secret: Vec<u8>) {
        self.keys.insert(id, secret);
    }
}

impl From<HashMap<String, Vec<u8>>> for MapKeyStore {
    fn from(keys: HashMap<String, Vec<u8>>) -> Self {
        MapKeyStore { keys }
    }
}

impl ApiKeyStore for MapKeyStore {
    fn get(&self, id: &str) -> Option<Vec<u8>> {
        self.keys.get(id).cloned()
    }
}

pub struct SessionStore {
    config: SessionConfig,
    sessions: Mutex<HashMap<u64, Session>>,
    next_id: AtomicU64,
}

impl SessionStore {
    pub fn new(config: SessionConfig) -> Self {
        SessionStore {
            config,
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn next_session_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn insert(&self, session: Session) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session.id, session);
    }

    pub fn get(&self, id: u64) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(&id).cloned()
    }

    pub fn delete(&self, id: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&id);
    }

    pub fn is_expired(&self, session: &Session) -> bool {
        session.created_at.elapsed() > self.config.max_lifetime
    }

    pub fn is_idle_dead(&self, session: &Session) -> bool {
        session.last_used.elapsed() > self.config.idle_timeout
    }

    pub fn gc(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.created_at.elapsed() <= self.config.max_lifetime);
    }

    pub fn len(&self) -> usize {
        let sessions = self.sessions.lock().unwrap();
        sessions.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        SessionStore::new(SessionConfig::default())
    }
}

// ── Handshake over sync Read/Write ─────────────────────────

use std::io::{Read, Write};

/// Client-side handshake (sync).
pub fn negotiate_client(
    stream: &mut (impl Read + Write),
    key: &ApiKey,
) -> Result<Session, SessionError> {
    let (secret, public) = generate_key_pair();
    let pub_bytes = public.to_bytes();

    let key_id_bytes = key.id.as_bytes();
    let mut buf = Vec::with_capacity(2 + key_id_bytes.len() + PUB_KEY_SIZE);
    buf.extend_from_slice(&(key_id_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(key_id_bytes);
    buf.extend_from_slice(&pub_bytes);
    stream.write_all(&buf).map_err(|e| SessionError::Crypto(format!("write: {}", e)))?;

    let mut resp = vec![0u8; PUB_KEY_SIZE + 8];
    stream.read_exact(&mut resp).map_err(|e| SessionError::Crypto(format!("read: {}", e)))?;

    let server_pub_bytes: [u8; PUB_KEY_SIZE] = resp[..PUB_KEY_SIZE]
        .try_into()
        .map_err(|_| SessionError::Crypto("invalid server pubkey".into()))?;
    let server_pub = PublicKey::from(server_pub_bytes);

    let session_id = u64::from_be_bytes(resp[PUB_KEY_SIZE..].try_into().unwrap());

    let shared = shared_secret(secret, &server_pub);
    let session_key = derive_session_key(shared.as_bytes(), &key.secret)?;

    Ok(Session::new(session_id, key.id.clone(), session_key))
}

/// Server-side handshake (sync).
pub fn negotiate_server(
    stream: &mut (impl Read + Write),
    server_secret: EphemeralSecret,
    server_public: &PublicKey,
    key_store: &dyn ApiKeyStore,
    next_id: u64,
) -> Result<Session, SessionError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).map_err(|e| SessionError::Crypto(format!("read header: {}", e)))?;
    let key_len = u16::from_be_bytes(header) as usize;

    if key_len == 0 || key_len > 256 {
        return Err(SessionError::Crypto("invalid key length".into()));
    }

    let mut key_buf = vec![0u8; key_len + PUB_KEY_SIZE];
    stream.read_exact(&mut key_buf).map_err(|e| SessionError::Crypto(format!("read key+pub: {}", e)))?;

    let api_key_id = String::from_utf8(key_buf[..key_len].to_vec())
        .map_err(|_| SessionError::Crypto("invalid utf-8 key id".into()))?;
    let client_pub_bytes: [u8; PUB_KEY_SIZE] = key_buf[key_len..]
        .try_into()
        .map_err(|_| SessionError::Crypto("invalid client pubkey".into()))?;
    let client_pub = PublicKey::from(client_pub_bytes);

    let api_key_secret = key_store.get(&api_key_id)
        .ok_or_else(|| SessionError::Crypto(format!("unknown api key id '{}'", api_key_id)))?;

    let server_pub_bytes = server_public.to_bytes();
    let session_id = next_id;

    let shared = shared_secret(server_secret, &client_pub);
    let session_key = derive_session_key(shared.as_bytes(), &api_key_secret)?;

    let mut resp = Vec::with_capacity(PUB_KEY_SIZE + 8);
    resp.extend_from_slice(&server_pub_bytes);
    resp.extend_from_slice(&session_id.to_be_bytes());
    stream.write_all(&resp).map_err(|e| SessionError::Crypto(format!("write response: {}", e)))?;

    Ok(Session::new(session_id, api_key_id, session_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key() {
        let key = ApiKey::generate();
        assert_eq!(key.id.len(), 16);
        assert_eq!(key.secret.len(), 32);
    }

    #[test]
    fn test_key_exchange() {
        let key = ApiKey::generate();
        let (client_priv, client_pub) = generate_key_pair();
        let (server_priv, server_pub) = generate_key_pair();

        let client_shared = shared_secret(client_priv, &server_pub);
        let server_shared = shared_secret(server_priv, &client_pub);

        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());

        let client_key = derive_session_key(client_shared.as_bytes(), &key.secret).unwrap();
        let server_key = derive_session_key(server_shared.as_bytes(), &key.secret).unwrap();

        assert_eq!(client_key, server_key);
        assert_eq!(client_key.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = ApiKey::generate();
        let plaintext = b"hello hush";
        let encrypted = encrypt(&key.secret, plaintext).unwrap();
        let decrypted = decrypt(&key.secret, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = ApiKey::generate();
        let key2 = ApiKey::generate();
        let encrypted = encrypt(&key1.secret, b"secret").unwrap();
        assert!(decrypt(&key2.secret, &encrypted).is_err());
    }

    #[test]
    fn test_handshake_roundtrip() {
        let key = ApiKey::generate();
        let (client_priv, client_pub) = generate_key_pair();
        let (server_priv, server_pub) = generate_key_pair();

        let client_shared = shared_secret(client_priv, &server_pub);
        let server_shared = shared_secret(server_priv, &client_pub);

        let client_key = derive_session_key(client_shared.as_bytes(), &key.secret).unwrap();
        let server_key = derive_session_key(server_shared.as_bytes(), &key.secret).unwrap();

        assert_eq!(client_key, server_key);
    }
}

// ── Static key support (for servers) ──────────────────────


/// Generate a static X25519 key pair for long-lived server use.
pub fn generate_static_key() -> StaticSecret {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    StaticSecret::from(bytes)
}

/// Compute ECDH shared secret from a static private key.
pub fn shared_secret_static(priv_key: &StaticSecret, pub_key: &PublicKey) -> SharedSecret {
    priv_key.diffie_hellman(pub_key)
}

impl SessionConfig {
    /// Return a config with zero values replaced by defaults.
    pub fn fill(self) -> Self {
        SessionConfig {
            idle_timeout: if self.idle_timeout <= Duration::ZERO { DEFAULT_IDLE_TIMEOUT } else { self.idle_timeout },
            max_lifetime: if self.max_lifetime <= Duration::ZERO { DEFAULT_MAX_LIFETIME } else { self.max_lifetime },
            gc_interval: if self.gc_interval <= Duration::ZERO { DEFAULT_GC_INTERVAL } else { self.gc_interval },
        }
    }
}

impl Clone for SessionConfig {
    fn clone(&self) -> Self {
        SessionConfig {
            idle_timeout: self.idle_timeout,
            max_lifetime: self.max_lifetime,
            gc_interval: self.gc_interval,
        }
    }
}
