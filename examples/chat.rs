use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};

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
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  cargo run --example chat server");
        eprintln!("  cargo run --example chat client <id> <secret> <port> <nick>");
        return;
    }

    match args[1].as_str() {
        "server" => run_server(),
        "client" => {
            if args.len() < 6 {
                eprintln!("Usage: cargo run --example chat client <id> <secret> <port> <nick>");
                return;
            }
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_client(&args[2], &args[3], &args[4], &args[5]));
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

    let (tx, _) = tokio::sync::broadcast::channel::<(String, String)>(256);

    let tx_c = tx.clone();
    srv.handle(0x0001, move |payload| {
        let nick = match payload.get_string("nick") {
            Some(n) => n.to_string(),
            None => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("nick required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };
        let msg = match payload.get_string("message") {
            Some(m) => m.to_string(),
            None => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("message required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };

        let _ = tx_c.send((nick, msg));

        let mut m = tlv::Map::new();
        m.set("sent", tlv::Value::Bool(true));
        Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
    });

    let tls = Server::load_tls("test-cert.pem", "test-key.pem").expect("load TLS");
    let endpoint = transport::bind("127.0.0.1:0", tls).expect("bind");
    let port = endpoint.local_addr().unwrap().port();

    eprintln!("[INF] Hush Chat ready on port {}", port);
    println!("Key ID:       {}", api_key.id);
    println!("Key Secret:   {}", hex::encode(&api_key.secret));
    println!("Port:         {}", port);
    println!("Join:         cargo run --example chat client {} {} {} <nick>", api_key.id, hex::encode(&api_key.secret), port);
    println!();

    rt.block_on(srv.listen_on(endpoint)).unwrap();
}

async fn run_client(key_id: &str, key_secret_hex: &str, port: &str, nick: &str) {
    let secret = hex::decode(key_secret_hex).expect("bad secret hex");
    let api_key = ApiKey { id: key_id.to_string(), secret };

    let client = hush::client::Client::dial(&format!("127.0.0.1:{}", port), &api_key, None)
        .await
        .expect("connect");

    println!("\n💬 Joined chat as {} (session {})", nick, client.session_id());
    println!("Type a message and press Enter. Ctrl+C to quit.\n");
    print!("> ");
    io::stdout().flush().ok();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let msg = line.unwrap_or_default();
        let msg = msg.trim().to_string();
        if msg.is_empty() {
            print!("> ");
            io::stdout().flush().ok();
            continue;
        }
        if msg == "/quit" || msg == "/exit" {
            break;
        }

        let mut m = tlv::Map::new();
        m.set("nick", tlv::Value::String(nick.to_string()));
        m.set("message", tlv::Value::String(msg));
        match client.do_(0x0001, Some(m)).await {
            Ok(_) => {}
            Err(e) => println!("send error: {}", e),
        }
        print!("> ");
        io::stdout().flush().ok();
    }
}
