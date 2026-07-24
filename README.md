# Hush 🔇 (Rust)

**Stealth-first API protocol — Rust implementation.**

This is the Rust crate for [Hush](https://github.com/feralbureau/hush-go), a network
protocol framework that makes your API invisible to standard tooling. This crate is a
1:1 mirror of [hush-go](https://github.com/feralbureau/hush-go) — same wire format,
same crypto, same semantics. A Go server and a Rust client interoperate seamlessly.

```toml
[dependencies]
hush = { git = "https://github.com/feralbureau/hush-rs" }
```

---

## Package Overview

```
src/
├── lib.rs         — re-exports
├── tlv.rs         — 15-type binary TLV (string, ints, floats, maps, arrays, …)
├── session.rs     — X25519 ECDH, AES-256-GCM, HKDF key derivation, session store
├── frame.rs       — length-prefixed frames, request/response encode/decode
├── transport.rs   — QUIC dial/bind via quinn (rustls + ring)
├── client.rs      — async client: dial() + do_()
├── server.rs      — async server: handle() + listen_on()
└── media.rs       — session-bound media token management
```

## Examples

| Example | Description | Run it |
|---------|-------------|--------|
| [Weather](examples/weather.rs) | Proxies [wttr.in](https://wttr.in) through Hush. External HTTP from a handler. | `cargo run --example weather server` → `client <key> <secret> <port> London` |
| [CRUD Notes](examples/crud.rs) | In-memory notes — create, list, get, update, delete. Multiple opcodes. | `cargo run --example crud server` → `client <key> <secret> <port>` |
| [Chat](examples/chat.rs) | Basic chat using a broadcast channel. | `cargo run --example chat server` → `client <key> <secret> <port> Alice` |

### Running the examples

```bash
# Generate TLS certs (one time)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout test-key.pem -out test-cert.pem -days 3650 -nodes \
  -subj "/CN=hush.test"

# Terminal 1 — start the server
cargo run --example weather server

# Terminal 2 — query weather (use the key, secret, and port from the server)
cargo run --example weather client <key_id> <key_secret_hex> <hush_port> London
```

## Running tests

```bash
cargo test
```

## License

MIT
