# Contributing to hush-rs

Thanks for wanting to contribute. Hush is a small, focused project — that's by design. Every addition should earn its keep.

## What fits

Hush is a **protocol framework**, not an application server. Good contributions:

- **Bug fixes** — anything in the 7 core modules
- **Performance** — faster serialization, fewer allocations, smarter crypto
- **Protocol extensions** — only if they're optional and don't bloat the core
- **Tests** — edge cases, fuzzing, interoperability
- **Documentation** — clearer examples, better explanations, fixing gaps
- **Examples** — new complete examples in [`examples/`](examples/) are welcome

What doesn't fit:

- **Application-layer features** — SoundCloud clients, auth dashboards, webhook integrations. Those are examples, not the library.
- **New transports** — unless there's a good case. TCP? WebSocket? Talk about it first.
- **Schema changes** — the TLV wire format and frame structure are set. Breaking changes won't be accepted.

## Before you start

If you're adding a feature or changing behaviour, open an issue first. Saves you writing code that won't merge.

## Running the examples

All examples are in [`examples/`](examples/). Test your changes against them:

```bash
# Generate TLS certs first (one time)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout test-key.pem -out test-cert.pem -days 3650 -nodes \
  -subj "/CN=hush.test"

# Build all examples
cargo build --examples

# Run a specific example
cargo run --example weather server
cargo run --example weather client <key> <secret> <port> London
```

## PR guidelines

- One change per PR. Small diffs get reviewed faster.
- All existing tests must pass. Add tests for new code.
- Run the examples to verify nothing is broken.
- Follow the existing style. There's no formatter config — just match the surrounding code.
- No vendored dependencies. Hush-rs has three real deps: `quinn`, `rustls`, and `x25519-dalek`. Think hard before adding a fourth.
- Keep the diff minimal. Don't reformat unrelated code.

## Running tests

```bash
cargo test
```

## Code of conduct

Don't be a jerk.
