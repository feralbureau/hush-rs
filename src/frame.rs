use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::{Read, Write};

use crate::session;
use crate::tlv;

pub const MAX_FRAME_SIZE: u32 = 1 << 20;
pub const FRAME_OVERHEAD: u32 = 4 + 12 + 16;
pub const FRAME_MIN_DATA: u32 = 4;

pub fn max_safe_payload() -> u32 {
    MAX_FRAME_SIZE - FRAME_OVERHEAD
}

pub fn wire_overhead() -> u32 {
    36
}


// ── Status Codes ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusCode {
    Success          = 0x00,
    BadRequest       = 0x01,
    Unauthenticated  = 0x02,
    PermissionDenied = 0x03,
    NotFound         = 0x04,
    SessionExpired   = 0x05,
    RateLimited      = 0x06,
    InternalError    = 0x07,
}

impl StatusCode {
    pub fn from_u8(b: u8) -> Option<StatusCode> {
        match b {
            0x00 => Some(StatusCode::Success),
            0x01 => Some(StatusCode::BadRequest),
            0x02 => Some(StatusCode::Unauthenticated),
            0x03 => Some(StatusCode::PermissionDenied),
            0x04 => Some(StatusCode::NotFound),
            0x05 => Some(StatusCode::SessionExpired),
            0x06 => Some(StatusCode::RateLimited),
            0x07 => Some(StatusCode::InternalError),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            StatusCode::Success => "success",
            StatusCode::BadRequest => "bad_request",
            StatusCode::Unauthenticated => "unauthenticated",
            StatusCode::PermissionDenied => "permission_denied",
            StatusCode::NotFound => "not_found",
            StatusCode::SessionExpired => "session_expired",
            StatusCode::RateLimited => "rate_limited",
            StatusCode::InternalError => "internal_error",
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub seq: u32,
    pub data: Vec<u8>,
}

// ── Async I/O ──────────────────────────────────────────────

/// Read a frame from an async reader.
pub async fn read_frame_async(r: &mut (impl AsyncReadExt + Unpin)) -> Result<Frame, FrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => FrameError::Eof,
        _ => FrameError::Io(e),
    })?;
    let frame_len = u32::from_be_bytes(len_buf);
    if frame_len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(frame_len, MAX_FRAME_SIZE));
    }
    if frame_len < FRAME_MIN_DATA {
        return Err(FrameError::TooShort(frame_len));
    }
    let mut data = vec![0u8; frame_len as usize];
    r.read_exact(&mut data).await.map_err(FrameError::Io)?;
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Ok(Frame { seq, data: data[4..].to_vec() })
}

/// Write a frame to an async writer.
pub async fn write_frame_async(w: &mut (impl AsyncWriteExt + Unpin), seq: u32, frame_data: &[u8]) -> Result<(), FrameError> {
    let total_len = 4u32 + frame_data.len() as u32;
    if total_len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(total_len, MAX_FRAME_SIZE));
    }
    let mut buf = Vec::with_capacity(4 + total_len as usize);
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(frame_data);
    w.write_all(&buf).await.map_err(FrameError::Io)
}

// ── Sync I/O (legacy) ──────────────────────────────────────


pub fn read_frame(r: &mut impl Read) -> Result<Frame, FrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => FrameError::Eof,
        _ => FrameError::Io(e),
    })?;
    let frame_len = u32::from_be_bytes(len_buf);
    if frame_len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(frame_len, MAX_FRAME_SIZE));
    }
    if frame_len < FRAME_MIN_DATA {
        return Err(FrameError::TooShort(frame_len));
    }
    let mut data = vec![0u8; frame_len as usize];
    r.read_exact(&mut data).map_err(FrameError::Io)?;
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Ok(Frame { seq, data: data[4..].to_vec() })
}

pub fn write_frame(w: &mut impl Write, seq: u32, frame_data: &[u8]) -> Result<(), FrameError> {
    let total_len = 4u32 + frame_data.len() as u32;
    if total_len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(total_len, MAX_FRAME_SIZE));
    }
    let mut buf = Vec::with_capacity(4 + total_len as usize);
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(frame_data);
    w.write_all(&buf).map_err(FrameError::Io)
}

// ── Raw byte helpers ────────────────────────────────────────

pub fn encode_frame(seq: u32, frame_data: &[u8]) -> Result<Vec<u8>, FrameError> {
    let total_len = 4u32 + frame_data.len() as u32;
    if total_len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(total_len, MAX_FRAME_SIZE));
    }
    let mut buf = Vec::with_capacity(4 + total_len as usize);
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(frame_data);
    Ok(buf)
}

pub fn parse_frame_data(data: &[u8]) -> Result<Frame, FrameError> {
    if data.len() < 4 {
        return Err(FrameError::TooShort(data.len() as u32));
    }
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Ok(Frame { seq, data: data[4..].to_vec() })
}

// ── Request ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Request {
    pub opcode: u16,
    pub payload: Option<tlv::Map>,
}

pub fn encode_request_body(key: Option<&[u8]>, req: &Request) -> Result<Vec<u8>, RequestError> {
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&req.opcode.to_be_bytes());
    if let Some(ref map) = req.payload {
        let tlv_data = tlv::encode_map(map);
        plaintext.extend_from_slice(&tlv_data);
    }
    match key {
        None => Ok(plaintext),
        Some(k) => session::encrypt(k, &plaintext).map_err(RequestError::Session),
    }
}

pub fn decode_request(key: Option<&[u8]>, wire_data: &[u8]) -> Result<(Request, u32), RequestError> {
    let frame = parse_frame_data(wire_data)?;
    let plaintext = match key {
        None => frame.data,
        Some(k) => session::decrypt(k, &frame.data).map_err(RequestError::Session)?,
    };
    if plaintext.len() < 2 {
        return Err(RequestError::TooShort);
    }
    let opcode = u16::from_be_bytes([plaintext[0], plaintext[1]]);
    let payload = if plaintext.len() > 2 {
        tlv::decode_map_opt(&plaintext[2..])
    } else {
        None
    };
    Ok((Request { opcode, payload }, frame.seq))
}

// ── Response ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Response {
    pub status: StatusCode,
    pub payload: Option<tlv::Map>,
    pub seq: u32,
}

pub fn encode_response_body(key: Option<&[u8]>, resp: &Response) -> Result<Vec<u8>, RequestError> {
    let mut plaintext = Vec::new();
    plaintext.push(resp.status as u8);
    if let Some(ref map) = resp.payload {
        let tlv_data = tlv::encode_map(map);
        plaintext.extend_from_slice(&tlv_data);
    }
    match key {
        None => Ok(plaintext),
        Some(k) => session::encrypt(k, &plaintext).map_err(RequestError::Session),
    }
}

pub fn decode_response(key: Option<&[u8]>, wire_data: &[u8]) -> Result<Response, RequestError> {
    let frame = parse_frame_data(wire_data)?;
    let plaintext = match key {
        None => frame.data,
        Some(k) => session::decrypt(k, &frame.data).map_err(RequestError::Session)?,
    };
    if plaintext.is_empty() {
        return Err(RequestError::TooShort);
    }
    let status = StatusCode::from_u8(plaintext[0])
        .ok_or(RequestError::UnknownStatus(plaintext[0]))?;
    let payload = if plaintext.len() > 1 {
        tlv::decode_map_opt(&plaintext[1..])
    } else {
        None
    };
    Ok(Response { status, payload, seq: frame.seq })
}

// ── Helpers ─────────────────────────────────────────────────

/// Create a successful response with a payload map.
pub fn new_response(payload: tlv::Map) -> Response {
    Response { status: StatusCode::Success, payload: Some(payload), seq: 0 }
}

/// Create an error response with a message.
pub fn error_response(code: StatusCode, message: &str) -> Response {
    let mut m = tlv::Map::new();
    m.set("error", tlv::Value::String(message.into()));
    Response { status: code, payload: Some(m), seq: 0 }
}

/// Read a full request from an async stream (async version).
pub async fn read_request_async(
    r: &mut (impl AsyncReadExt + Unpin),
    key: Option<&[u8]>,
) -> Result<(Request, u32), RequestError> {
    let frame = read_frame_async(r).await?;
    let mut wire = frame.seq.to_be_bytes().to_vec();
    wire.extend_from_slice(&frame.data);
    decode_request(key, &wire)
}
pub async fn write_response_async(
    w: &mut (impl AsyncWriteExt + Unpin),
    key: Option<&[u8]>,
    seq: u32,
    resp: &Response,
) -> Result<(), RequestError> {
    let body = encode_response_body(key, resp)?;
    write_frame_async(w, seq, &body).await.map_err(|e| RequestError::Frame(e.into()))?;
    Ok(())
}

// ── Errors ──────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum FrameError {
    #[error("frame: eof")]
    Eof,
    #[error("frame: io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame: too large ({0} bytes, max {1})")]
    TooLarge(u32, u32),
    #[error("frame: too short ({0} bytes)")]
    TooShort(u32),
}

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("session: {0}")]
    Session(#[from] session::SessionError),
    #[error("frame: request too short")]
    TooShort,
    #[error("frame: unknown status code {0}")]
    UnknownStatus(u8),
    #[error("frame: io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, 42, b"hello").unwrap();
        let frame = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(frame.seq, 42);
        assert_eq!(frame.data, b"hello");
    }

    #[test]
    fn test_request_response_encrypted() {
        let key = session::ApiKey::generate();
        let mut map = tlv::Map::new();
        map.set("name", tlv::Value::String("hush".into()));

        let req = Request { opcode: 0x0001, payload: Some(map) };

        let body = encode_request_body(Some(&key.secret), &req).unwrap();
        let frame_bytes = encode_frame(1, &body).unwrap();
        let (decoded, _) = decode_request(Some(&key.secret), &frame_bytes[4..]).unwrap();

        assert_eq!(decoded.opcode, 0x0001);
        assert_eq!(decoded.payload.unwrap().get_string("name"), Some("hush"));
    }

    #[test]
    fn test_response_roundtrip() {
        let key = session::ApiKey::generate();
        let resp = Response {
            status: StatusCode::NotFound,
            payload: None,
            seq: 0,
        };

        let body = encode_response_body(Some(&key.secret), &resp).unwrap();
        let frame_bytes = encode_frame(1, &body).unwrap();
        let decoded = decode_response(Some(&key.secret), &frame_bytes[4..]).unwrap();

        assert_eq!(decoded.status, StatusCode::NotFound);
    }
}
