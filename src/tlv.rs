
use std::time::Duration;
use thiserror::Error;

// ── Types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Type {
    String    = 0x01,
    Bytes     = 0x02,
    Uint8     = 0x03,
    Uint16    = 0x04,
    Uint32    = 0x05,
    Uint64    = 0x06,
    Int32     = 0x07,
    Int64     = 0x08,
    Float32   = 0x09,
    Float64   = 0x0A,
    Bool      = 0x0B,
    Array     = 0x0C,
    Map       = 0x0D,
    Null      = 0x0E,
    Timestamp = 0x0F,
}

impl Type {
    fn from_u8(b: u8) -> Option<Type> {
        match b {
            0x01 => Some(Type::String),
            0x02 => Some(Type::Bytes),
            0x03 => Some(Type::Uint8),
            0x04 => Some(Type::Uint16),
            0x05 => Some(Type::Uint32),
            0x06 => Some(Type::Uint64),
            0x07 => Some(Type::Int32),
            0x08 => Some(Type::Int64),
            0x09 => Some(Type::Float32),
            0x0A => Some(Type::Float64),
            0x0B => Some(Type::Bool),
            0x0C => Some(Type::Array),
            0x0D => Some(Type::Map),
            0x0E => Some(Type::Null),
            0x0F => Some(Type::Timestamp),
            _ => None,
        }
    }
}

#[derive(Error, Debug)]
pub enum TlvError {
    #[error("tlv: {0}")]
    Custom(String),
}

impl From<&str> for TlvError {
    fn from(s: &str) -> Self {
        TlvError::Custom(s.to_string())
    }
}

// ── Value ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Bytes(Vec<u8>),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Int32(i32),
    Int64(i64),
    Float32(f32),
    Float64(f64),
    Bool(bool),
    Array(Vec<Value>),
    Map(Map),
    Null,
    Timestamp(Duration),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Map {
    entries: Vec<(String, Value)>,
}

impl Map {
    pub fn new() -> Self {
        Map { entries: Vec::new() }
    }

    pub fn set<K: Into<String>>(&mut self, key: K, value: Value) -> &mut Self {
        let key = key.into();
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.entries.push((key, value));
        }
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn get_uint64(&self, key: &str) -> Option<u64> {
        match self.get(key)? {
            Value::Uint64(n) => Some(*n),
            _ => None,
        }
    }

    pub fn get_bytes(&self, key: &str) -> Option<&[u8]> {
        match self.get(key)? {
            Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn get_map(&self, key: &str) -> Option<Map> {
        match self.get(key)? {
            Value::Map(m) => Some(m.clone()),
            _ => None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    
/// Wrap a Map into a Value for use in nested containers.
pub fn map_value(m: &Map) -> Value {
    Value::Map(m.clone())
}

pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for Map {
    fn default() -> Self {
        Map::new()
    }
}

impl IntoIterator for Map {
    type Item = (String, Value);
    type IntoIter = std::vec::IntoIter<(String, Value)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

// ── Encode ──────────────────────────────────────────────────

const MAX_PAYLOAD_SIZE: u64 = 524288;
const MAX_DECODE_DEPTH: usize = 64;

pub fn encode(v: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_into(v, &mut buf).expect("tlv encode failed");
    buf
}

fn encode_into(v: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    let payload = payload_bytes(v)?;
    let typ_byte = type_byte(v);
    buf.push(typ_byte);
    encode_varint(payload.len() as u64, buf);
    buf.extend_from_slice(&payload);
    Ok(())
}

fn type_byte(v: &Value) -> u8 {
    match v {
        Value::String(_) => 0x01,
        Value::Bytes(_) => 0x02,
        Value::Uint8(_) => 0x03,
        Value::Uint16(_) => 0x04,
        Value::Uint32(_) => 0x05,
        Value::Uint64(_) => 0x06,
        Value::Int32(_) => 0x07,
        Value::Int64(_) => 0x08,
        Value::Float32(_) => 0x09,
        Value::Float64(_) => 0x0A,
        Value::Bool(_) => 0x0B,
        Value::Array(_) => 0x0C,
        Value::Map(_) => 0x0D,
        Value::Null => 0x0E,
        Value::Timestamp(_) => 0x0F,
    }
}

fn payload_bytes(v: &Value) -> Result<Vec<u8>, String> {
    Ok(match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Bytes(b) => b.clone(),
        Value::Uint8(n) => vec![*n],
        Value::Uint16(n) => n.to_be_bytes().to_vec(),
        Value::Uint32(n) => n.to_be_bytes().to_vec(),
        Value::Uint64(n) => n.to_be_bytes().to_vec(),
        Value::Int32(n) => (*n as u32).to_be_bytes().to_vec(),
        Value::Int64(n) => (*n as u64).to_be_bytes().to_vec(),
        Value::Float32(f) => f.to_bits().to_be_bytes().to_vec(),
        Value::Float64(f) => f.to_bits().to_be_bytes().to_vec(),
        Value::Bool(b) => vec![if *b { 1u8 } else { 0u8 }],
        Value::Null => Vec::new(),
        Value::Timestamp(d) => (d.as_millis() as u64).to_be_bytes().to_vec(),
        Value::Array(items) => {
            let mut buf = Vec::new();
            for item in items {
                encode_into(item, &mut buf)?;
            }
            buf
        }
        Value::Map(m) => {
            let mut buf = Vec::new();
            for (key, val) in &m.entries {
                encode_into(&Value::String(key.clone()), &mut buf)?;
                encode_into(val, &mut buf)?;
            }
            buf
        }
    })
}

// ── Decode ──────────────────────────────────────────────────

pub fn decode(buf: &[u8]) -> Result<Value, String> {
    let mut pos = 0;
    let (val, _) = decode_value(buf, &mut pos, 0)?;
    Ok(val)
}

pub fn decode_map(buf: &[u8]) -> Result<Map, String> {
    let val = decode(buf)?;
    match val {
        Value::Map(m) => Ok(m),
        _ => Err("tlv: expected map".to_string()),
    }
}

fn decode_value(buf: &[u8], pos: &mut usize, depth: usize) -> Result<(Value, usize), String> {
    if depth > MAX_DECODE_DEPTH {
        return Err(format!("tlv: nested depth {} exceeds max {}", depth, MAX_DECODE_DEPTH));
    }

    if *pos >= buf.len() {
        return Err("tlv: unexpected EOF".to_string());
    }

    let typ_byte = buf[*pos];
    *pos += 1;

    let typ = Type::from_u8(typ_byte)
        .ok_or_else(|| format!("tlv: unknown type 0x{:02x}", typ_byte))?;

    let (len, adv) = decode_varint(&buf[*pos..])
        .map_err(|e| format!("tlv: decode varint: {}", e))?;
    *pos += adv;

    if len > MAX_PAYLOAD_SIZE {
        return Err(format!("tlv: payload too large ({} bytes, max {})", len, MAX_PAYLOAD_SIZE));
    }

    let payload_start = *pos;
    let payload_end = payload_start + len as usize;
    if payload_end > buf.len() {
        return Err("tlv: payload exceeds buffer".to_string());
    }
    *pos = payload_end;

    let payload = &buf[payload_start..payload_end];

    let value = match typ {
        Type::String => Value::String(
            String::from_utf8(payload.to_vec())
                .map_err(|_| "tlv: invalid utf-8 string")?
        ),
        Type::Bytes => Value::Bytes(payload.to_vec()),
        Type::Uint8 => {
            if payload.len() < 1 { return Err("tlv: uint8 needs 1 byte".to_string()); }
            Value::Uint8(payload[0])
        }
        Type::Uint16 => {
            if payload.len() < 2 { return Err("tlv: uint16 needs 2 bytes".to_string()); }
            Value::Uint16(u16::from_be_bytes([payload[0], payload[1]]))
        }
        Type::Uint32 => {
            if payload.len() < 4 { return Err("tlv: uint32 needs 4 bytes".to_string()); }
            Value::Uint32(u32::from_be_bytes(
                [payload[0], payload[1], payload[2], payload[3]]
            ))
        }
        Type::Uint64 => {
            if payload.len() < 8 { return Err("tlv: uint64 needs 8 bytes".to_string()); }
            Value::Uint64(u64::from_be_bytes(
                [payload[0], payload[1], payload[2], payload[3],
                 payload[4], payload[5], payload[6], payload[7]]
            ))
        }
        Type::Int32 => {
            if payload.len() < 4 { return Err("tlv: int32 needs 4 bytes".to_string()); }
            let bits = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            Value::Int32(bits as i32)
        }
        Type::Int64 => {
            if payload.len() < 8 { return Err("tlv: int64 needs 8 bytes".to_string()); }
            let bits = u64::from_be_bytes(
                [payload[0], payload[1], payload[2], payload[3],
                 payload[4], payload[5], payload[6], payload[7]]
            );
            Value::Int64(bits as i64)
        }
        Type::Float32 => {
            if payload.len() < 4 { return Err("tlv: float32 needs 4 bytes".to_string()); }
            let bits = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            Value::Float32(f32::from_bits(bits))
        }
        Type::Float64 => {
            if payload.len() < 8 { return Err("tlv: float64 needs 8 bytes".to_string()); }
            let bits = u64::from_be_bytes(
                [payload[0], payload[1], payload[2], payload[3],
                 payload[4], payload[5], payload[6], payload[7]]
            );
            Value::Float64(f64::from_bits(bits))
        }
        Type::Bool => {
            if payload.len() < 1 { return Err("tlv: bool needs 1 byte".to_string()); }
            Value::Bool(payload[0] != 0)
        }
        Type::Null => Value::Null,
        Type::Timestamp => {
            if payload.len() < 8 { return Err("tlv: timestamp needs 8 bytes".to_string()); }
            let ms = u64::from_be_bytes(
                [payload[0], payload[1], payload[2], payload[3],
                 payload[4], payload[5], payload[6], payload[7]]
            );
            Value::Timestamp(Duration::from_millis(ms))
        }
        Type::Array => {
            let mut items = Vec::new();
            let mut p = 0;
            while p < payload.len() {
                let (item, _consumed) = decode_value(payload, &mut p, depth + 1)?;
                items.push(item);
            }
            Value::Array(items)
        }
        Type::Map => {
            let mut m = Map::new();
            let mut p = 0;
            while p < payload.len() {
                let (key_val, _consumed) = decode_value(payload, &mut p, depth + 1)?;
                let key = match &key_val {
                    Value::String(s) => s.clone(),
                    _ => return Err("tlv: map key must be string".to_string()),
                };
                if p >= payload.len() {
                    return Err(format!("tlv: map entry missing value for key '{}'", key));
                }
                let (val, _consumed2) = decode_value(payload, &mut p, depth + 1)?;
                m.set(key, val);
            }
            Value::Map(m)
        }
    };

    Ok((value, *pos))
}

// ── Varint ──────────────────────────────────────────────────

fn encode_varint(mut n: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if n == 0 {
            break;
        }
    }
}

fn decode_varint(buf: &[u8]) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if i >= 10 {
            return Err("varint too long".to_string());
        }
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err("unterminated varint".to_string())
}

// ── Helper functions ───────────────────────────────────────

pub fn encode_map(m: &Map) -> Vec<u8> {
    encode(&Value::Map(m.clone()))
}

pub fn decode_map_opt(buf: &[u8]) -> Option<Map> {
    if buf.is_empty() {
        return None;
    }
    decode_map(buf).ok()
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: &Value) {
        let encoded = encode(v);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(*v, decoded);
    }

    #[test]
    fn test_string() { roundtrip(&Value::String("hello hush".into())); }
    #[test]
    fn test_bytes() { roundtrip(&Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])); }
    #[test]
    fn test_u8() { roundtrip(&Value::Uint8(255)); }
    #[test]
    fn test_u16() { roundtrip(&Value::Uint16(65535)); }
    #[test]
    fn test_u32() { roundtrip(&Value::Uint32(4294967295)); }
    #[test]
    fn test_u64() { roundtrip(&Value::Uint64(u64::MAX)); }
    #[test]
    fn test_i32() { roundtrip(&Value::Int32(-2147483648)); }
    #[test]
    fn test_i64() { roundtrip(&Value::Int64(-9223372036854775808)); }
    #[test]
    fn test_f32() { roundtrip(&Value::Float32(3.14159)); }
    #[test]
    fn test_f64() { roundtrip(&Value::Float64(2.718281828459045)); }
    #[test]
    fn test_bool() { roundtrip(&Value::Bool(true)); }
    #[test]
    fn test_null() { roundtrip(&Value::Null); }
    #[test]
    fn test_timestamp() { roundtrip(&Value::Timestamp(Duration::from_millis(1700000000000))); }

    #[test]
    fn test_array() {
        let v = Value::Array(vec![
            Value::String("a".into()),
            Value::Uint64(42),
            Value::Bool(true),
        ]);
        roundtrip(&v);
    }

    #[test]
    fn test_map() {
        let mut m = Map::new();
        m.set("name", Value::String("hush".into()));
        m.set("version", Value::Uint64(1));
        roundtrip(&Value::Map(m));
    }

    #[test]
    fn test_nested_map() {
        let mut inner = Map::new();
        inner.set("x", Value::Uint32(100));
        let mut outer = Map::new();
        outer.set("inner", Value::Map(inner));
        roundtrip(&Value::Map(outer));
    }

    #[test]
    fn test_empty_map() { roundtrip(&Value::Map(Map::new())); }

    #[test]
    fn test_large_string() {
        roundtrip(&Value::String("a".repeat(10000)));
    }

    #[test]
    fn test_max_depth() {
        let mut v = Value::Uint64(1);
        for _ in 0..MAX_DECODE_DEPTH {
            v = Value::Array(vec![v]);
        }
        let encoded = encode(&v);
        assert!(decode(&encoded).is_ok());
    }

    #[test]
    fn test_exceeds_max_depth() {
        let mut v = Value::Uint64(1);
        for _ in 0..=MAX_DECODE_DEPTH {
            v = Value::Array(vec![v]);
        }
        let encoded = encode(&v);
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn test_map_overwrite() {
        let mut m = Map::new();
        m.set("key", Value::Uint64(1));
        m.set("key", Value::Uint64(2));
        assert_eq!(m.get_uint64("key"), Some(2));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn test_unknown_type() {
        assert!(decode(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn test_oversized_payload() {
        assert!(decode(&[0x02, 0x80, 0x80, 0x80, 0x80, 0x08]).is_err());
    }
}
