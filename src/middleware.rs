//! Middleware — composable request-processing chains.
//!
//! Middleware wraps a handler to add cross-cutting behaviour such as
//! logging, authentication, rate-limiting, or panic recovery.

use std::sync::Arc;
use std::time::Instant;

use crate::logger::Logger;
use crate::server::{Request, SyncHandler, StreamHandler};

/// Middleware wraps a synchronous handler and returns a new one.
pub type Middleware = Arc<dyn Fn(SyncHandler) -> SyncHandler + Send + Sync>;

/// StreamMiddleware wraps a streaming handler.
pub type StreamMiddleware = Arc<dyn Fn(StreamHandler) -> StreamHandler + Send + Sync>;

// ── Constructors ───────────────────────────────────────────

/// Create a Middleware from a plain closure.
pub fn mw_fn<F>(f: F) -> Middleware
where
    F: Fn(SyncHandler) -> SyncHandler + Send + Sync + 'static,
{
    Arc::new(f)
}

/// Create a StreamMiddleware from a plain closure.
pub fn stream_mw_fn<F>(f: F) -> StreamMiddleware
where
    F: Fn(StreamHandler) -> StreamHandler + Send + Sync + 'static,
{
    Arc::new(f)
}

// ── Built-in middleware ────────────────────────────────────

/// Logging middleware — logs opcode, elapsed time, and status.
pub fn logging_middleware(logger: Option<Arc<Logger>>) -> Middleware {
    mw_fn(move |next| {
        let log = logger.clone();
        Arc::new(move |req: Request| {
            let opcode = req.opcode;
            let start = Instant::now();
            let result = next(req);
            let elapsed = start.elapsed();
            if let Some(ref l) = log {
                match &result {
                    Ok(resp) => l.info(format_args!(
                        "[MW] opcode=0x{opcode:04x} status={} elapsed={}s",
                        resp.status as u8,
                        elapsed.as_secs_f64(),
                    )),
                    Err(e) => l.warn(format_args!(
                        "[MW] opcode=0x{opcode:04x} ERROR elapsed={}s err={e}",
                        elapsed.as_secs_f64(),
                    )),
                }
            }
            result
        })
    })
}

/// Panic-recovery middleware — catches panics and returns InternalError.
pub fn recovery_middleware() -> Middleware {
    mw_fn(|next| {
        Arc::new(move |req: Request| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                next(req)
            })) {
                Ok(result) => result,
                Err(_) => {
                    eprintln!("[MW] PANIC recovered in opcode handler");
                    Err("internal error (panic)".into())
                }
            }
        })
    })
}

/// Rate-limiting middleware — rejects requests once a limit is exceeded.
pub fn rate_limit_middleware<L>(limiter: Arc<L>, max: u64) -> Middleware
where
    L: Fn() -> u64 + Send + Sync + 'static,
{
    mw_fn(move |next| {
        let lim = limiter.clone();
        Arc::new(move |req: Request| {
            if (lim)() > max {
                return Err("rate limit exceeded".into());
            }
            next(req)
        })
    })
}

/// Require a specific API key ID.
pub fn require_api_key_id(allowed: Vec<String>) -> Middleware {
    mw_fn(move |next| {
        let ids = allowed.clone();
        Arc::new(move |req: Request| {
            if !ids.contains(&req.api_key_id) {
                return Err(format!("api key '{}' not authorized", req.api_key_id));
            }
            next(req)
        })
    })
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Response, StatusCode};
    use crate::server::Request;
    use crate::tlv;
    fn ok_handler() -> SyncHandler {
        Arc::new(|_req: Request| {
            Ok(Response {
                status: StatusCode::Success,
                payload: Some(tlv::Map::new()),
                seq: 0,
            })
        })
    }

    fn err_handler() -> SyncHandler {
        Arc::new(|_req: Request| {
            Err("oops".into())
        })
    }

    #[test]
    fn test_middleware_passthrough() {
        let mw = logging_middleware(None);
        let wrapped = mw(ok_handler());
        let req = Request {
            opcode: 0x0101,
            payload: tlv::Map::new(),
            session_id: 1,
            api_key_id: "test".into(),
        };
        let resp = wrapped(req).unwrap();
        assert_eq!(resp.status, StatusCode::Success);
    }

    #[test]
    fn test_recovery_middleware() {
        let mw = recovery_middleware();
        let panic_handler: SyncHandler = Arc::new(|_req: Request| {
            panic!("boom");
        });
        let wrapped = mw(panic_handler);
        let req = Request {
            opcode: 0x0101,
            payload: tlv::Map::new(),
            session_id: 1,
            api_key_id: "test".into(),
        };
        let result = wrapped(req);
        assert!(result.is_err());
    }

    #[test]
    fn test_require_api_key() {
        let mw = require_api_key_id(vec!["admin".into()]);
        let wrapped = mw(ok_handler());

        let req = Request {
            opcode: 0x0101,
            payload: tlv::Map::new(),
            session_id: 1,
            api_key_id: "admin".into(),
        };
        assert!(wrapped(req).is_ok());

        let req = Request {
            opcode: 0x0101,
            payload: tlv::Map::new(),
            session_id: 1,
            api_key_id: "hacker".into(),
        };
        assert!(wrapped(req).is_err());
    }
}
