//! Session-bound media token management — mirrors hush-go/media.

use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_MAX_TOKEN_TTL: Duration = Duration::from_secs(7200); // 2h

#[derive(Debug, Clone)]
pub struct Token {
    pub id: [u8; 16],
    pub track_id: String,
    pub hls_url: String,
    pub created_at: Instant,
    pub issued_at: Instant,
    pub session_id: u64,
}

pub struct TokenStore {
    inner: Mutex<Inner>,
    validate_session: Option<Box<dyn Send + Sync + Fn(u64) -> bool>>,
    pub max_token_ttl: Duration,
}

struct Inner {
    tokens: HashMap<[u8; 16], Token>,
}

impl TokenStore {
    pub fn new() -> Self {
        TokenStore {
            inner: Mutex::new(Inner { tokens: HashMap::new() }),
            validate_session: None,
            max_token_ttl: DEFAULT_MAX_TOKEN_TTL,
        }
    }

    pub fn with_validator(validate_session: impl Send + Sync + Fn(u64) -> bool + 'static) -> Self {
        TokenStore {
            inner: Mutex::new(Inner { tokens: HashMap::new() }),
            validate_session: Some(Box::new(validate_session)),
            max_token_ttl: DEFAULT_MAX_TOKEN_TTL,
        }
    }

    pub fn issue(&self, session_id: u64, track_id: &str) -> Token {
        self.issue_with_hls(session_id, track_id, "")
    }

    pub fn issue_with_hls(&self, session_id: u64, track_id: &str, hls_url: &str) -> Token {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);

        let now = Instant::now();
        let tok = Token {
            id,
            track_id: track_id.into(),
            hls_url: hls_url.into(),
            created_at: now,
            issued_at: now,
            session_id,
        };

        let mut inner = self.inner.lock().unwrap();
        inner.tokens.insert(id, tok.clone());
        tok
    }

    pub fn validate(&self, token_id: &[u8; 16]) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let tok = match inner.tokens.get(token_id) {
            Some(t) => t,
            None => return false,
        };

        if tok.issued_at.elapsed() > self.max_token_ttl {
            inner.tokens.remove(token_id);
            return false;
        }

        if let Some(ref validate) = self.validate_session {
            if !validate(tok.session_id) {
                inner.tokens.remove(token_id);
                return false;
            }
        }

        // Extend created_at
        if let Some(t) = inner.tokens.get_mut(token_id) {
            t.created_at = Instant::now();
        }
        true
    }

    pub fn exists(&self, token_id: &[u8; 16]) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.tokens.contains_key(token_id)
    }

    pub fn lookup_hls(&self, token_id: &[u8; 16]) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.tokens.get(token_id).map(|t| t.hls_url.clone())
    }

    pub fn gc(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.tokens.retain(|_, t| t.issued_at.elapsed() <= self.max_token_ttl);
    }
}

pub struct MediaURLBuilder {
    pub base_url: String,
}

impl MediaURLBuilder {
    pub fn new(base_url: &str) -> Self {
        MediaURLBuilder { base_url: base_url.into() }
    }

    pub fn build_url(&self, token_id: &[u8; 16], track_id: &str) -> String {
        format!("{}/media/{}/{}", self.base_url, hex::encode(token_id), track_id)
    }
}
