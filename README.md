# hush-rs

**Stealth-first API protocol for Rust.**

Hush is a network protocol framework that makes your API invisible to standard
tooling. No HTTP endpoints to discover, no readable request structure, no replay
attacks. It runs over QUIC with a custom ALPN, encodes payloads in a compact
binary TLV format, and encrypts every frame with per-session AES-256-GCM keys.

```toml
[dependencies]
hush = { git = "https://github.com/feralbureau/hush-rs" }
```

This is the Rust implementation of Hush. It mirrors [hush-go](https://github.com/feralbureau/hush-go)
exactly — same wire format, same crypto, same semantics. A hush-go server and a
hush-rs client interoperate seamlessly.

---

## Why Hush

| REST problem | Hush fix |
|---|---|
| Anybody can open DevTools and replicate requests | Custom ALPN `hush/1` — HTTP tools can't connect |
| API surface is fully observable | Binary TLV + AEAD — no readable structure |
| Trivial to fuzz and pentest | Session-bound encryption + sequence numbers |
| Unofficial clients are easy to write | Per-session ephemeral ECDH keys make replay useless |
| gRPC is bloated and painful | TLV instead of protobuf, no codegen, no schema files |

You can disable any of these protections when you don't need them (see
[Configuration](#configuration)).

---

## Quick Start

### Prerequisites

- Rust 1.75+
- Clone the repo and generate a test TLS certificate:

```bash
git clone https://github.com/feralbureau/hush-rs.git
cd hush-rs

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout test-key.pem -out test-cert.pem -days 3650 -nodes \
  -subj "/CN=hush.test"
```

### Run an example

Every [example](examples/) is a single `.rs` file. Start the server, then run
the client using the key, secret, and port it prints.

```bash
# Terminal 1 — start the server
cargo run --example weather server

# Terminal 2 — query weather
cargo run --example weather client <key_id> <key_secret_hex> <hush_port> London
```

### Minimal API (without examples)

If you just want to write a server from scratch:

```rust
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use hush::frame::{Response, StatusCode};
use hush::session::{ApiKey, ApiKeyStore};
use hush::server::Server;
use hush::tlv;
use hush::transport;

struct KeyStore(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl ApiKeyStore for KeyStore {
    fn get(&self, id: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(id).cloned()
    }
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let api_key = ApiKey::generate();

    let mut keys = HashMap::new();
    keys.insert(api_key.id.clone(), api_key.secret.clone());
    let store = KeyStore(Arc::new(Mutex::new(keys)));

    let srv = Server::new(store);

    srv.handle(0x0001, |payload| {
        let name = payload.get_string("name").unwrap_or("world").to_string();
        let mut m = tlv::Map::new();
        m.set("greeting", tlv::Value::String(format!("hello, {}", name)));
        Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
    });

    let tls = Server::load_tls("test-cert.pem", "test-key.pem").expect("load TLS");
    let endpoint = transport::bind("127.0.0.1:0", tls).expect("bind");
    let port = endpoint.local_addr().unwrap().port();
    eprintln!("listening on port {}", port);

    rt.block_on(srv.listen_on(endpoint)).unwrap();
}
```

And the matching client:

```rust
use hush::session::ApiKey;
use hush::tlv;
use hush::client::Client;

#[tokio::main]
async fn main() {
    let api_key = ApiKey { id: "<id>".into(), secret: hex::decode("<secret>").unwrap() };

    let client = Client::dial("127.0.0.1:<port>", &api_key, None).await.unwrap();

    let mut m = tlv::Map::new();
    m.set("name", tlv::Value::String("world".into()));
    let resp = client.do_(0x0001, Some(m)).await.unwrap();

    let greeting = resp.payload.as_ref()
        .and_then(|p| p.get_string("greeting")).unwrap_or("?");
    println!("{}", greeting);
}
```

---

## Module Overview

```
src/
├── transport.rs   QUIC dial/bind with configurable ALPN
├── session.rs     X25519 key exchange, AES-256-GCM, session store
├── frame.rs       Length-prefixed encrypted/plaintext wire frames
├── tlv.rs         Binary TLV serialization (string, ints, floats, maps, arrays)
├── client.rs      High-level async client (connect, send, receive)
├── server.rs      High-level async server (TLS, sessions, handler dispatch)
└── media.rs       Session-bound media tokens for HTTP media delivery
```

### `transport` — QUIC connectivity

```rust
use hush::transport;

// Bind a QUIC endpoint (server)
let endpoint = transport::bind("127.0.0.1:443", tls_config)?;

// Dial a QUIC connection (client)
let (conn, _endpoint) = transport::dial("127.0.0.1:443", Some(client_tls)).await?;
```

### `session` — Key exchange, crypto, configuration

```
POST-QUIC HANDSHAKE:
  Client ──► api_key_id + X25519_pub ──► Server
  Client ◄── X25519_pub + session_id  ◄── Server
  Both: shared = ECDH(priv, peer_pub)
        key = HKDF-SHA256(salt=shared, ikm=api_key_secret, info="hush-v1-key")
```

```rust
use hush::session::{self, ApiKey, ApiKeyStore};

// Generate API keys
let api_key = ApiKey::generate();

// Low-level handshake
let (priv_key, pub_key) = session::generate_key_pair();
let shared = session::shared_secret(priv_key, &server_pub);
let session_key = session::derive_session_key(shared.as_bytes(), &api_key.secret)?;

// Key store trait
pub trait ApiKeyStore: Send + Sync {
    fn get(&self, id: &str) -> Option<Vec<u8>>;
}

// Session store with configurable timeouts
let store = SessionStore::new(SessionConfig {
    idle_timeout: Duration::from_secs(300),
    max_lifetime: Duration::from_secs(86400),
    gc_interval: Duration::from_secs(60),
    ..Default::default()
});
```

### `frame` — Wire format

Every request/response is a single QUIC stream containing one frame:

```
4 bytes: frame_length (big-endian)
4 bytes: sequence_number (big-endian)
N bytes: frame_data
```

When **encrypted** (`key != None`):

```
frame_data = nonce (12) || AES-256-GCM ciphertext || tag (16)
```

When **plaintext** (`key == None`):

```
frame_data = raw plaintext bytes
```

```rust
use hush::frame;

// Encrypted (default)
let body = frame::encode_request_body(Some(&session_key), &req)?;
let frame_bytes = frame::encode_frame(seq, &body)?;

let frame = frame::parse_frame_data(&frame_bytes[4..])?;
let (req, seq) = frame::decode_request(Some(&session_key), &frame_bytes[4..])?;

// Plaintext (no encryption)
let body = frame::encode_request_body(None, &req)?;
let (req, seq) = frame::decode_request(None, &frame_bytes[4..])?;
```

#### Allowed opcode ranges

Opcodes are `u16`. The convention is:

| Range | Use |
|-------|-----|
| `0x0000` | Reserved (server push events) |
| `0x0001`–`0x00FF` | System |
| `0x0100`–`0x7FFF` | Application |
| `0x8000`–`0xFFFF` | Reserved for future Hush extensions |

### `tlv` — Binary payload serialization

Compact, no schema files, no codegen. The wire format is:

```
type (1 byte) || length (LEB128 varint) || value (length bytes)
```

**Supported types:**

| Type | Rust constructor | Rust accessor |
|------|---|---|
| String | `tlv::Value::String(s)` | `.get_string(key)` |
| Bytes | `tlv::Value::Bytes(b)` | `.get_bytes(key)` |
| Uint8 | `tlv::Value::Uint8(n)` | — |
| Uint16 | `tlv::Value::Uint16(n)` | — |
| Uint32 | `tlv::Value::Uint32(n)` | — |
| Uint64 | `tlv::Value::Uint64(n)` | `.get_uint64(key)` |
| Int32 | `tlv::Value::Int32(n)` | — |
| Int64 | `tlv::Value::Int64(n)` | — |
| Float32 | `tlv::Value::Float32(f)` | — |
| Float64 | `tlv::Value::Float64(f)` | — |
| Bool | `tlv::Value::Bool(b)` | — |
| Array | `tlv::Value::Array(vals)` | — |
| Map | `tlv::Value::Map(m)` | `.get_map(key)` |
| Timestamp | `tlv::Value::Timestamp(d)` | — |
| Null | `tlv::Value::Null` | — |

**Maps — the primary payload structure:**

```rust
use hush::tlv::{self, Map, Value};

let mut payload = Map::new();
payload.set("name", Value::String("alice".into()));
payload.set("count", Value::Uint64(42));
payload.set("nested", Value::Map({
    let mut m = Map::new();
    m.set("key", Value::Bool(true));
    m
}));

// Reading
let name = payload.get_string("name").unwrap();       // "alice"
let count = payload.get_uint64("count").unwrap();      // 42
let nested = payload.get_map("nested").unwrap();
```

### `client` — High-level client

```rust
use hush::client::Client;
use hush::session::ApiKey;
use hush::tlv;

let api_key = ApiKey { id: "abc".into(), secret: vec![/* 32 bytes */] };
let client = Client::dial("127.0.0.1:443", &api_key, None).await?;

let response = client.do_(0x0001, Some(tlv::Map::new())).await?;
let sid = client.session_id();
```

### `server` — High-level server

```rust
use hush::server::Server;
use hush::frame::{Response, StatusCode};
use hush::tlv;

let srv = Server::new(key_store);

// Standard request-response handler
srv.handle(0x0001, |payload| {
    let mut m = tlv::Map::new();
    m.set("ok", tlv::Value::Bool(true));
    Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
});

// Bind and listen
let tls = Server::load_tls("test-cert.pem", "test-key.pem")?;
let endpoint = transport::bind("127.0.0.1:443", tls)?;
rt.block_on(srv.listen_on(endpoint)).unwrap();
```

**Server methods:**

| Method | Purpose |
|--------|---------|
| `Server::new(key_store)` | Create a new server |
| `srv.handle(opcode, fn)` | Register a request handler |
| `Server::load_tls(cert, key)` | Load TLS certificate files |
| `srv.listen_on(endpoint)` | Accept connections on a QUIC endpoint |

### `media` — Media token management

For serving large files (images, audio, HLS streams) over HTTPS, Hush uses
session-bound media tokens. The QUIC session handles API calls; a companion
HTTPS server handles media delivery.

```rust
use hush::media::{TokenStore, MediaURLBuilder};

let store = TokenStore::with_validator(|session_id: u64| {
    // Check if session is still alive
    true
});

// Issue a token bound to a session
let tok = store.issue(session_id, "track-abc");

// Validate and extend (for initial access)
let valid = store.validate(&tok.id);

// Lightweight existence check (for HLS segment proxying)
let exists = store.exists(&tok.id);

// Absolute TTL (configurable)
store.max_token_ttl = Duration::from_secs(1800); // 30 min

// Build media URLs
let builder = MediaURLBuilder::new("https://media.example.com");
let url = builder.build_url(&tok.id, "track-abc");
// → "https://media.example.com/media/ab12.../track-abc"
```

---

## Examples

| Example | Description | Run it |
|---------|-------------|--------|
| [Weather](examples/weather.rs) | Calls [wttr.in](https://wttr.in) through Hush. External HTTP from a handler. | `cargo run --example weather server` → `client <key> <secret> <port> London` |
| [CRUD Notes](examples/crud.rs) | In-memory notes — create, list, get, update, delete. Multiple opcodes. | `cargo run --example crud server` → `client <key> <secret> <port>` |
| [Chat](examples/chat.rs) | Real-time chat using a broadcast channel. | `cargo run --example chat server` → `client <key> <secret> <port> Alice` |

All three follow the same pattern:

```bash
# Terminal 1 — start the server
cargo run --example weather server

# Terminal 2 — use the key, secret, and port it prints
cargo run --example weather client <key_id> <key_secret_hex> <hush_port> London
```

---

## Configuration

Everything in Hush is configurable. Here's every tuning point:

### Encryption on/off

Pass `None` instead of a session key to read/write plaintext frames:

```rust
frame::encode_request_body(None, &req);          // no encryption
frame::decode_request(None, &wire_data);          // no decryption
```

### Session timeouts

```rust
let store = SessionStore::new(SessionConfig {
    idle_timeout: Duration::from_secs(600),   // default: 5m
    max_lifetime: Duration::from_secs(172800), // default: 24h
    gc_interval: Duration::from_secs(30),      // default: 1m
});
```

### Media token TTL

```rust
store.max_token_ttl = Duration::from_secs(600); // default: 2h
```

### Logging

```rust
// Set log level via env var
std::env::set_var("RUST_LOG", "info");
env_logger::init();
```

---

## Wire Protocol Reference

### Frame format

```
frame_length (uint32 BE) || frame_data
```

**Encrypted frame_data:**

```
sequence_number (uint32 BE) || nonce (12 bytes) || ciphertext || AEAD tag (16 bytes)
```

**Plaintext frame_data:**

```
sequence_number (uint32 BE) || plaintext
```

### Request plaintext

```
opcode (uint16 BE) || tlv_payload (optional)
```

### Response plaintext

```
status_code (uint8) || tlv_payload (optional)
```

### Status codes

| Code | Name |
|------|------|
| `0x00` | Success |
| `0x01` | Bad request |
| `0x02` | Unauthenticated |
| `0x03` | Permission denied |
| `0x04` | Not found |
| `0x05` | Session expired |
| `0x06` | Rate limited |
| `0x07` | Internal error |
| `0x80+` | Application-defined |

### Session handshake

```
Client → Server:  api_key_id_len (uint16 BE) || api_key_id || X25519_pubkey (32 bytes)
Server → Client:  X25519_pubkey (32 bytes) || session_id (uint64 BE)

Shared secret = ECDH(client_priv, server_pub)
Session key   = HKDF-SHA256(ikm=api_key_secret, salt=shared_secret, info="hush-v1-key")
```

---

## Security Model

| Threat | Mitigation |
|---|---|
| Eavesdropping | TLS 1.3 + AES-256-GCM per frame |
| Replay attacks | Per-frame sequence number, per-session keys |
| API key theft | Keys are PSK for ECDH — never sent after handshake |
| Observability | Custom ALPN, binary wire format, no readable structure |
| Fuzzing | Invalid frames fail AEAD decryption at the transport layer |
| Session hijack | Session ID is tied to ECDH-derived key |

### Tradeoffs

- **Browser support**: Hush uses raw QUIC — browsers can't open WebSocket-style
  connections to it. For web clients, run an HTTPS or WebSocket bridge.
- **Complexity**: QUIC + custom crypto is heavier than plain HTTP. You're trading
  simplicity for stealth.
- **Debugging**: No curl, no Postman, no DevTools. Use the included client, or
  run in plaintext mode (`key == None`) during development.

---

## Project Structure

```
src/
├── transport.rs   QUIC dial/bind, configurable ALPN
├── session.rs     X25519 key exchange, AES-256-GCM, session store
├── frame.rs       Length-prefixed encrypted/plaintext wire frames
├── tlv.rs         Binary TLV encode/decode, all types
├── client.rs      High-level async client
├── server.rs      High-level async server, handler dispatch
├── media.rs       Session-bound media token store
├── test-cert.pem  TLS cert for local testing
└── test-key.pem   TLS key for local testing
```

---

## Contributing

Contributions are welcome. Before opening a pull request, please read the [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
