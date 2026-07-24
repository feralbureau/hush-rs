use std::io::{Read, Write};
use thiserror::Error;

use crate::session;
use crate::tlv;

pub const MAX_FRAME_SIZE: u32 = 1 << 20;
pub const FRAME_OVERHEAD: u32 = 4 + 12 + 16;
pub const FRAME_MIN_DATA: u32 = 4;

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
}

#[derive(Debug)]
pub struct Frame {
    pub seq: u32,
    pub data: Vec<u8>,
}

// ── Sync I/O ────────────────────────────────────────────────

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

/// Encode a frame into wire bytes: [4-byte len][4-byte seq][data].
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

/// Parse a frame from wire bytes that include the seq prefix.
/// Input: [4-byte seq][frame_data] (no length prefix).
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

/// Encode a request body (opcode + optional tlv), optionally encrypted.
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

/// Decode a request from frame data (after length stripping).
/// Input: [4-byte seq][encrypted/plaintext payload].
/// Output: (Request, seq).
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

/// Encode a response body (status + optional tlv), optionally encrypted.
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

/// Decode a response from frame data (after length stripping).
/// Input: [4-byte seq][encrypted/plaintext payload].
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

        // Encode body
        let body = encode_request_body(Some(&key.secret), &req).unwrap();
        // Wrap in frame
        let frame_bytes = encode_frame(1, &body).unwrap();
        // frame_bytes = [4-byte len][4-byte seq][encrypted body]
        // strip the 4-byte len prefix for decode
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
