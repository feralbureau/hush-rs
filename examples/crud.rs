// Hush example: CRUD notes.
//
// In-memory notes with Create, List, Get, Update, Delete.
//
// Usage:
//   Terminal 1: cargo run --example crud server
//   Terminal 2: cargo run --example crud client <id> <secret> <port>
use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hush::frame::{Response, StatusCode};
use hush::server::{Request, Server};
use hush::session::{ApiKey, ApiKeyStore};
use hush::tlv;
use hush::transport;

struct KeyStore(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl ApiKeyStore for KeyStore {
    fn get(&self, id: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(id).cloned()
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  cargo run --example crud server");
        eprintln!("  cargo run --example crud client <id> <secret> <port>");
        return;
    }

    match args[1].as_str() {
        "server" => run_server(),
        "client" => {
            if args.len() < 5 {
                eprintln!("Usage: cargo run --example crud client <id> <secret> <port>");
                return;
            }
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_client(&args[2], &args[3], &args[4]));
        }
        other => eprintln!("unknown command: {}", other),
    }
}

fn run_server() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let api_key = ApiKey::generate();

    let mut keys = HashMap::new();
    keys.insert(api_key.id.clone(), api_key.secret.clone());
    let store = KeyStore(Arc::new(Mutex::new(keys)));

    let srv = Server::new(store);

    let notes: Arc<Mutex<HashMap<u64, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_id = Arc::new(AtomicU64::new(1));

    // 0x0001 — Create
    let notes_c = notes.clone();
    let nid_c = next_id.clone();
    srv.handle(0x0001, move |req: Request| {
        let text = match req.payload.get_string("text") {
            Some(t) => t.to_string(),
            None => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("text required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };
        let id = nid_c.fetch_add(1, Ordering::SeqCst);
        notes_c.lock().unwrap().insert(id, text);
        let mut m = tlv::Map::new();
        m.set("id", tlv::Value::Uint64(id));
        Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
    });

    // 0x0002 — List
    let notes_l = notes.clone();
    srv.handle(0x0002, move |_req: Request| {
        let snapshot = notes_l.lock().unwrap().clone();
        let mut items = Vec::new();
        for (id, text) in &snapshot {
            let mut m = tlv::Map::new();
            m.set("id", tlv::Value::Uint64(*id));
            m.set("text", tlv::Value::String(text.clone()));
            items.push(tlv::Value::Map(m));
        }
        let mut m = tlv::Map::new();
        m.set("notes", tlv::Value::Array(items));
        m.set("count", tlv::Value::Uint64(snapshot.len() as u64));
        Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
    });

    // 0x0003 — Get
    let notes_g = notes.clone();
    srv.handle(0x0003, move |req: Request| {
        let id = match req.payload.get_uint64("id") {
            Some(id) if id != 0 => id,
            _ => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("id required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };
        let snapshot = notes_g.lock().unwrap().clone();
        match snapshot.get(&id) {
            Some(text) => {
                let mut m = tlv::Map::new();
                m.set("id", tlv::Value::Uint64(id));
                m.set("text", tlv::Value::String(text.clone()));
                Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
            }
            None => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("note not found".into()));
                Ok(Response { status: StatusCode::NotFound, payload: Some(m), seq: 0 })
            }
        }
    });

    // 0x0004 — Update
    let notes_u = notes.clone();
    srv.handle(0x0004, move |req: Request| {
        let id = match req.payload.get_uint64("id") {
            Some(id) if id != 0 => id,
            _ => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("id required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };
        let text = match req.payload.get_string("text") {
            Some(t) => t.to_string(),
            None => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("text required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };
        let mut n = notes_u.lock().unwrap();
        if n.contains_key(&id) {
            n.insert(id, text);
            let mut m = tlv::Map::new();
            m.set("id", tlv::Value::Uint64(id));
            m.set("updated", tlv::Value::Bool(true));
            Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
        } else {
            let mut m = tlv::Map::new();
            m.set("error", tlv::Value::String("note not found".into()));
            Ok(Response { status: StatusCode::NotFound, payload: Some(m), seq: 0 })
        }
    });

    // 0x0005 — Delete
    let notes_d = notes.clone();
    srv.handle(0x0005, move |req: Request| {
        let id = match req.payload.get_uint64("id") {
            Some(id) if id != 0 => id,
            _ => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("id required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };
        let existed = notes_d.lock().unwrap().remove(&id).is_some();
        let mut m = tlv::Map::new();
        m.set("deleted", tlv::Value::Bool(existed));
        Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
    });

    let tls = Server::load_tls("test-cert.pem", "test-key.pem").expect("load TLS");
    let endpoint = transport::bind("127.0.0.1:0", tls).expect("bind");
    let port = endpoint.local_addr().unwrap().port();

    eprintln!("[INF] Hush CRUD Notes ready on port {}", port);
    println!("Key ID:       {}", api_key.id);
    println!("Key Secret:   {}", hex::encode(&api_key.secret));
    println!("Port:         {}", port);
    println!("Ops:");
    println!("  0x0001  Create(text)     → id");
    println!("  0x0002  List()           → notes[]");
    println!("  0x0003  Get(id)          → note");
    println!("  0x0004  Update(id, text) → ok");
    println!("  0x0005  Delete(id)       → ok");
    println!();

    rt.block_on(srv.listen_on(endpoint)).unwrap();
}

async fn run_client(key_id: &str, key_secret_hex: &str, port: &str) {
    let secret = hex::decode(key_secret_hex).expect("bad secret hex");
    let api_key = ApiKey { id: key_id.to_string(), secret };

    let client = hush::client::Client::dial(&format!("127.0.0.1:{}", port), &api_key, None)
        .await
        .expect("connect");

    println!("Session: {}\n", client.session_id());

    let titles = vec!["buy milk", "call mom", "fix the bug"];
    let mut ids = Vec::new();
    for title in &titles {
        let mut m = tlv::Map::new();
        m.set("text", tlv::Value::String(title.to_string()));
        let resp = client.do_(0x0001, Some(m)).await.expect("create");
        let id = resp.payload.as_ref().and_then(|p| p.get_uint64("id")).unwrap();
        ids.push(id);
        println!("✅ Created note {}: {}", id, title);
    }

    let resp = client.do_(0x0002, None).await.expect("list");
    let count = resp.payload.as_ref().and_then(|p| p.get_uint64("count")).unwrap_or(0);
    println!("\n📋 {} notes total", count);
    if let Some(notes_val) = resp.payload.as_ref().and_then(|p| p.get("notes")) {
        if let tlv::Value::Array(items) = notes_val {
            for item in items {
                if let tlv::Value::Map(ref m) = item {
                    let id = m.get_uint64("id").unwrap_or(0);
                    let text = m.get_string("text").unwrap_or("?");
                    println!("   {}: {}", id, text);
                }
            }
        }
    }

    let mut m = tlv::Map::new();
    m.set("id", tlv::Value::Uint64(ids[0]));
    m.set("text", tlv::Value::String("buy milk and eggs".into()));
    client.do_(0x0004, Some(m)).await.expect("update");
    println!("\n✏️  Updated note {}", ids[0]);

    let mut m = tlv::Map::new();
    m.set("id", tlv::Value::Uint64(ids[0]));
    let resp = client.do_(0x0003, Some(m)).await.expect("get");
    let text = resp.payload.as_ref().and_then(|p| p.get_string("text")).unwrap_or("?");
    println!("🔍  Note {}: {}", ids[0], text);

    let mut m = tlv::Map::new();
    m.set("id", tlv::Value::Uint64(ids[2]));
    client.do_(0x0005, Some(m)).await.expect("delete");
    println!("🗑️  Deleted note {}", ids[2]);

    let resp = client.do_(0x0002, None).await.expect("list");
    let count = resp.payload.as_ref().and_then(|p| p.get_uint64("count")).unwrap_or(0);
    println!("\n📋 {} notes remaining", count);
    if let Some(notes_val) = resp.payload.as_ref().and_then(|p| p.get("notes")) {
        if let tlv::Value::Array(items) = notes_val {
            for item in items {
                if let tlv::Value::Map(ref m) = item {
                    let id = m.get_uint64("id").unwrap_or(0);
                    let text = m.get_string("text").unwrap_or("?");
                    println!("   {}: {}", id, text);
                }
            }
        }
    }
}
