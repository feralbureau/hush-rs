// Hush example: Weather API.
//
// Server proxies wttr.in through Hush. Client queries weather by city name.
//
// Usage:
//   Terminal 1: cargo run --example weather server
//   Terminal 2: cargo run --example weather client <key_id> <key_secret_hex> <hush_port> <city>

use std::env;
use std::collections::HashMap;
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
        eprintln!("  cargo run --example weather server");
        eprintln!("  cargo run --example weather client <id> <secret> <port> <city>");
        return;
    }

    match args[1].as_str() {
        "server" => run_server(),
        "client" => {
            if args.len() < 6 {
                eprintln!("Usage: cargo run --example weather client <id> <secret> <port> <city>");
                return;
            }
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_client(&args[2], &args[3], &args[4], &args[5]));
        }
        other => eprintln!("unknown command: {}", other),
    }
}

fn run_server() {
    let api_key = ApiKey::generate();

    let mut keys = HashMap::new();
    keys.insert(api_key.id.clone(), api_key.secret.clone());
    let store = KeyStore(Arc::new(Mutex::new(keys)));

    let srv = Server::new(store);

    srv.handle(0x0001, |payload| {
        let city = match payload.get_string("city") {
            Some(c) => c.to_string(),
            None => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String("city required".into()));
                return Ok(Response { status: StatusCode::BadRequest, payload: Some(m), seq: 0 });
            }
        };

        let url = format!("https://wttr.in/{}?format=%C+%t+%w+%h", city);
        let resp = ureq::get(&url)
            .set("User-Agent", "curl/8.0")
            .call();

        match resp {
            Ok(r) => {
                let body = r.into_string().unwrap_or_default();
                let mut m = tlv::Map::new();
                m.set("city", tlv::Value::String(city));
                m.set("weather", tlv::Value::String(body));
                Ok(Response { status: StatusCode::Success, payload: Some(m), seq: 0 })
            }
            Err(e) => {
                let mut m = tlv::Map::new();
                m.set("error", tlv::Value::String(format!("fetch failed: {}", e)));
                Ok(Response { status: StatusCode::InternalError, payload: Some(m), seq: 0 })
            }
        }
    });

    let tls = Server::load_tls("test-cert.pem", "test-key.pem").expect("load TLS");
    let endpoint = transport::bind("127.0.0.1:0", tls).expect("bind");
    let port = endpoint.local_addr().unwrap().port();

    eprintln!("[INF] Hush Weather ready on port {}", port);
    println!("Key ID:       {}", api_key.id);
    println!("Key Secret:   {}", hex::encode(&api_key.secret));
    println!("Port:         {}", port);
    println!("Try:          cargo run --example weather client {} {} {} London", api_key.id, hex::encode(&api_key.secret), port);
    println!();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(srv.listen_on(endpoint)).unwrap();
}

async fn run_client(key_id: &str, key_secret_hex: &str, port: &str, city: &str) {
    let secret = hex::decode(key_secret_hex).expect("bad secret hex");
    let api_key = ApiKey { id: key_id.to_string(), secret };

    let addr = format!("127.0.0.1:{}", port);
    let client = hush::client::Client::dial(&addr, &api_key, None)
        .await
        .expect("connect");

    let response = client
        .do_(0x0001, Some({
            let mut m = tlv::Map::new();
            m.set("city", tlv::Value::String(city.to_string()));
            m
        }))
        .await
        .expect("request");

    if response.status != StatusCode::Success {
        let err = response.payload.as_ref().and_then(|p| p.get_string("error")).unwrap_or("unknown");
        eprintln!("error: {}", err);
        return;
    }

    let weather = response.payload.as_ref().and_then(|p| p.get_string("weather")).unwrap_or("???");
    println!("\n🌍  {}", city);
    println!("🌤   {}", weather);
}
