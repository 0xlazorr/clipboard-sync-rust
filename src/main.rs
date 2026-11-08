use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROTOCOL_MAGIC: &[u8; 4] = b"CS02";
const MAX_PAYLOAD_SIZE: usize = 25 * 1024 * 1024; // 25 MB
const REPLAY_WINDOW_SECS: u64 = 60;

// =====================================================================
// Finite State Machines (FSM)
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncEngineState {
    Uninitialized,
    Discovering,
    Ready,
    Transferring,
    Error,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardItemState {
    Idle,
    Captured,
    Encrypted,
    Transmitted,
    Delivered,
    Received,
    Authenticating,
    Decrypted,
    Applied,
    Rejected,
}

pub struct SyncEngineFSM {
    state: SyncEngineState,
}

impl SyncEngineFSM {
    pub fn new() -> Self {
        Self {
            state: SyncEngineState::Uninitialized,
        }
    }

    pub fn current_state(&self) -> SyncEngineState {
        self.state
    }

    pub fn transition_to(&mut self, next: SyncEngineState, reason: &str) -> Result<(), String> {
        if self.state == next {
            return Ok(());
        }

        let is_valid = match (self.state, next) {
            (SyncEngineState::Uninitialized, SyncEngineState::Discovering)
            | (SyncEngineState::Uninitialized, SyncEngineState::Ready)
            | (SyncEngineState::Uninitialized, SyncEngineState::Stopped) => true,

            (SyncEngineState::Discovering, SyncEngineState::Ready)
            | (SyncEngineState::Discovering, SyncEngineState::Error)
            | (SyncEngineState::Discovering, SyncEngineState::Stopped) => true,

            (SyncEngineState::Ready, SyncEngineState::Transferring)
            | (SyncEngineState::Ready, SyncEngineState::Discovering)
            | (SyncEngineState::Ready, SyncEngineState::Error)
            | (SyncEngineState::Ready, SyncEngineState::Stopped) => true,

            (SyncEngineState::Transferring, SyncEngineState::Ready)
            | (SyncEngineState::Transferring, SyncEngineState::Discovering)
            | (SyncEngineState::Transferring, SyncEngineState::Error)
            | (SyncEngineState::Transferring, SyncEngineState::Stopped) => true,

            (SyncEngineState::Error, SyncEngineState::Discovering)
            | (SyncEngineState::Error, SyncEngineState::Ready)
            | (SyncEngineState::Error, SyncEngineState::Stopped) => true,

            (SyncEngineState::Stopped, SyncEngineState::Uninitialized) => true,

            _ => false,
        };

        if !is_valid {
            return Err(format!(
                "Illegal state transition from {:?} to {:?} (reason: {})",
                self.state, next, reason
            ));
        }

        self.state = next;
        Ok(())
    }
}

// =====================================================================
// Cryptographic Engine (HMAC-SHA256, PBKDF2, Keystream CTR)
// =====================================================================

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

fn derive_master_key(secret: &str) -> [u8; 32] {
    let salt = b"ClipboardSyncSalt_v2_PrivacyGuard";
    let mut salt_and_int = Vec::with_capacity(salt.len() + 4);
    salt_and_int.extend_from_slice(salt);
    salt_and_int.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(secret.as_bytes(), &salt_and_int);
    let mut result = u;

    // 10,000 PBKDF2 iterations matching protocol v2
    for _ in 1..10000 {
        u = hmac_sha256(secret.as_bytes(), &u);
        for i in 0..32 {
            result[i] ^= u[i];
        }
    }
    result
}

fn xor_keystream(key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut block_idx: u64 = 0;

    for chunk in data.chunks(32) {
        let mut seed = Vec::with_capacity(24);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(&block_idx.to_be_bytes());
        let block_key = hmac_sha256(key, &seed);

        for (i, byte) in chunk.iter().enumerate() {
            output.push(byte ^ block_key[i]);
        }
        block_idx += 1;
    }
    output
}

fn generate_random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let time_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p1 = Sha256::digest(&time_nanos.to_le_bytes());
    nonce.copy_from_slice(&p1[..16]);
    nonce
}

fn pack_packet(key: &[u8; 32], pkt_type: u8, payload: &[u8]) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let nonce = generate_random_nonce();
    let encrypted = xor_keystream(key, &nonce, payload);
    let length = encrypted.len() as u32;

    let mut header = Vec::with_capacity(65);
    header.extend_from_slice(PROTOCOL_MAGIC);
    header.push(pkt_type);
    header.extend_from_slice(&now.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    header.extend_from_slice(&nonce);

    let mut auth_input = Vec::with_capacity(header.len() + encrypted.len());
    auth_input.extend_from_slice(&header);
    auth_input.extend_from_slice(&encrypted);
    let tag = hmac_sha256(key, &auth_input);

    let mut packet = Vec::with_capacity(header.len() + 32 + encrypted.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&tag);
    packet.extend_from_slice(&encrypted);
    packet
}

fn unpack_packet(key: &[u8; 32], raw: &[u8]) -> Result<(u8, Vec<u8>), String> {
    if raw.len() < 65 {
        return Err(format!("Packet too short: {} bytes", raw.len()));
    }

    if &raw[0..4] != PROTOCOL_MAGIC {
        return Err("Invalid protocol magic bytes".to_string());
    }

    let pkt_type = raw[4];
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&raw[5..13]);
    let ts = u64::from_be_bytes(ts_bytes);

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&raw[13..17]);
    let length = u32::from_be_bytes(len_bytes) as usize;

    if length > MAX_PAYLOAD_SIZE {
        return Err(format!("Payload exceeds maximum size: {} bytes", length));
    }

    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&raw[17..33]);

    let mut tag = [0u8; 32];
    tag.copy_from_slice(&raw[33..65]);

    let encrypted = &raw[65..];
    if encrypted.len() != length {
        return Err(format!("Length mismatch: expected {}, got {}", length, encrypted.len()));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let diff = if now >= ts { now - ts } else { ts - now };
    if diff > REPLAY_WINDOW_SECS {
        return Err(format!("Expired packet: timestamp skew {}s", diff));
    }

    let mut auth_input = Vec::with_capacity(33 + encrypted.len());
    auth_input.extend_from_slice(&raw[0..33]);
    auth_input.extend_from_slice(encrypted);
    let expected_tag = hmac_sha256(key, &auth_input);

    if tag != expected_tag {
        return Err("HMAC verification failed (unauthorized or tampered payload)".to_string());
    }

    let decrypted = xor_keystream(key, &nonce, encrypted);
    Ok((pkt_type, decrypted))
}

// =====================================================================
// Configuration and State
// =====================================================================

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Config {
    secret_key: String,
    peer_ip: String,
    port: u16,
    discovery_port: u16,
    enable_discovery: bool,
    poll_interval: f32,
}

#[derive(Clone)]
enum ClipboardData {
    Text(String),
    Image(Vec<u8>),
}

struct ClipboardState {
    last_hash: Option<String>,
}

impl ClipboardState {
    fn new() -> Self {
        Self { last_hash: None }
    }

    fn calculate_hash(data: &ClipboardData) -> String {
        let mut hasher = Sha256::new();
        match data {
            ClipboardData::Text(text) => hasher.update(text.as_bytes()),
            ClipboardData::Image(bytes) => hasher.update(bytes),
        }
        let full = format!("{:x}", hasher.finalize());
        full[..12].to_string()
    }

    fn update_received(&mut self, hash: String) {
        self.last_hash = Some(hash);
    }

    fn check_and_update_sent(&mut self, hash: String) -> bool {
        if self.last_hash.as_ref() == Some(&hash) {
            false
        } else {
            self.last_hash = Some(hash);
            true
        }
    }
}

fn load_config() -> Config {
    let config_path = Path::new("config.json");
    if !config_path.exists() {
        let default_config = Config {
            secret_key: "REPLACE_WITH_YOUR_SHARED_SECRET_KEY".to_string(),
            peer_ip: "192.168.1.100".to_string(),
            port: 9999,
            discovery_port: 9998,
            enable_discovery: true,
            poll_interval: 1.0,
        };
        let file = File::create(config_path).expect("Unable to create default config.json");
        serde_json::to_writer_pretty(file, &default_config).expect("Unable to write default config.json");
        return default_config;
    }

    let mut file = File::open(config_path).expect("Unable to open config.json");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Unable to read config.json");
    serde_json::from_str(&contents).unwrap_or_else(|e| {
        println!("[-] Error parsing config.json: {}. Using default values.", e);
        Config {
            secret_key: "REPLACE_WITH_YOUR_SHARED_SECRET_KEY".to_string(),
            peer_ip: "192.168.1.100".to_string(),
            port: 9999,
            discovery_port: 9998,
            enable_discovery: true,
            poll_interval: 1.0,
        }
    })
}

fn is_wayland() -> bool {
    env::var("WAYLAND_DISPLAY").is_ok()
        || env::var("XDG_SESSION_TYPE").unwrap_or_default().to_lowercase().contains("wayland")
}

fn get_linux_clipboard(wayland: bool) -> Option<ClipboardData> {
    if wayland {
        if let Ok(output) = Command::new("wl-paste").arg("--list-types").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("image/png") {
                if let Ok(res) = Command::new("wl-paste").arg("-t").arg("image/png").output() {
                    if res.status.success() && !res.stdout.is_empty() {
                        return Some(ClipboardData::Image(res.stdout));
                    }
                }
            }
        }
        if let Ok(res) = Command::new("wl-paste").arg("-t").arg("text/plain").output() {
            if res.status.success() && !res.stdout.is_empty() {
                return Some(ClipboardData::Text(String::from_utf8_lossy(&res.stdout).into_owned()));
            }
        }
    } else {
        if let Ok(output) = Command::new("xclip").args(["-selection", "clipboard", "-o", "-t", "TARGETS"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("image/png") {
                if let Ok(res) = Command::new("xclip").args(["-selection", "clipboard", "-t", "image/png", "-o"]).output() {
                    if res.status.success() && !res.stdout.is_empty() {
                        return Some(ClipboardData::Image(res.stdout));
                    }
                }
            }
            let target = if stdout.contains("UTF8_STRING") { "UTF8_STRING" } else { "STRING" };
            if let Ok(res) = Command::new("xclip").args(["-selection", "clipboard", "-t", target, "-o"]).output() {
                if res.status.success() && !res.stdout.is_empty() {
                    return Some(ClipboardData::Text(String::from_utf8_lossy(&res.stdout).into_owned()));
                }
            }
        }
    }
    None
}

fn set_linux_clipboard(wayland: bool, data: &ClipboardData) {
    let (cmd, args) = if wayland {
        match data {
            ClipboardData::Text(_) => ("wl-copy", vec!["-t", "text/plain"]),
            ClipboardData::Image(_) => ("wl-copy", vec!["-t", "image/png"]),
        }
    } else {
        match data {
            ClipboardData::Text(_) => ("xclip", vec!["-selection", "clipboard", "-t", "UTF8_STRING", "-i"]),
            ClipboardData::Image(_) => ("xclip", vec!["-selection", "clipboard", "-t", "image/png", "-i"]),
        }
    };

    if let Ok(mut process) = Command::new(cmd).args(args).stdin(Stdio::piped()).spawn() {
        if let Some(mut stdin) = process.stdin.take() {
            match data {
                ClipboardData::Text(text) => {
                    let _ = stdin.write_all(text.as_bytes());
                }
                ClipboardData::Image(bytes) => {
                    let _ = stdin.write_all(bytes);
                }
            }
        }
        let _ = process.wait();
    }
}

// =====================================================================
// Networking Engine
// =====================================================================

fn send_to_peer(peer_ip: &str, port: u16, key: &[u8; 32], data: &ClipboardData) -> io::Result<()> {
    let (pkt_type, payload) = match data {
        ClipboardData::Text(text) => (0u8, text.as_bytes()),
        ClipboardData::Image(bytes) => (1u8, bytes.as_slice()),
    };

    let packet = pack_packet(key, pkt_type, payload);
    let address = format!("{}:{}", peer_ip, port);
    let addr: std::net::SocketAddr = address
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.write_all(&packet)?;
    Ok(())
}

fn run_server(port: u16, wayland: bool, key: [u8; 32], state: Arc<Mutex<ClipboardState>>) {
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[-] Could not bind TCP server on port {}: {}", port, e);
            return;
        }
    };
    println!("[+] Secure Rust TCP Server listening on port {}...", port);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state_clone = Arc::clone(&state);
                let thread_key = key;
                thread::spawn(move || {
                    let mut buffer = Vec::new();
                    let mut temp = [0u8; 4096];
                    loop {
                        match stream.read(&mut temp) {
                            Ok(0) => break,
                            Ok(n) => {
                                buffer.extend_from_slice(&temp[..n]);
                                if buffer.len() > MAX_PAYLOAD_SIZE + 65 {
                                    eprintln!("[-] Incoming payload exceeded safety threshold");
                                    return;
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    match unpack_packet(&thread_key, &buffer) {
                        Ok((pkt_type, decrypted)) => {
                            let data = if pkt_type == 0 {
                                let text = String::from_utf8_lossy(&decrypted).into_owned();
                                ClipboardData::Text(text)
                            } else {
                                ClipboardData::Image(decrypted)
                            };

                            let hash = ClipboardState::calculate_hash(&data);
                            println!("[+] Received authenticated sync (hash: {}). Updating clipboard.", hash);

                            {
                                let mut guard = state_clone.lock().unwrap();
                                guard.update_received(hash);
                            }

                            set_linux_clipboard(wayland, &data);
                        }
                        Err(e) => {
                            eprintln!("[-] Rejected unauthenticated packet: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("[-] Error accepting stream: {}", e);
            }
        }
    }
}

fn main() {
    let config = load_config();
    let wayland = is_wayland();
    println!("[+] Session Display Server Type: {}", if wayland { "WAYLAND" } else { "X11" });

    let mut fsm = SyncEngineFSM::new();
    let _ = fsm.transition_to(SyncEngineState::Discovering, "Startup");

    let master_key = derive_master_key(&config.secret_key);
    let state = Arc::new(Mutex::new(ClipboardState::new()));

    // Populate initial hash if clipboard has content
    if let Some(init_data) = get_linux_clipboard(wayland) {
        let hash = ClipboardState::calculate_hash(&init_data);
        state.lock().unwrap().update_received(hash);
    }

    // Start background receiver server
    let server_state = Arc::clone(&state);
    let server_port = config.port;
    thread::spawn(move || {
        run_server(server_port, wayland, master_key, server_state);
    });

    let interval = Duration::from_secs_f32(config.poll_interval);
    println!("[+] Secure Clipboard Monitor started. Polling every {}s...", config.poll_interval);

    let _ = fsm.transition_to(SyncEngineState::Ready, "Listening");

    loop {
        if let Some(data) = get_linux_clipboard(wayland) {
            let hash = ClipboardState::calculate_hash(&data);
            let should_send = {
                let mut guard = state.lock().unwrap();
                guard.check_and_update_sent(hash.clone())
            };

            if should_send {
                let _ = fsm.transition_to(SyncEngineState::Transferring, "Outbound sync");
                println!("[*] Local change detected (hash: {}). Encrypting and syncing to {}:{}...", hash, config.peer_ip, config.port);
                match send_to_peer(&config.peer_ip, config.port, &master_key, &data) {
                    Ok(_) => {
                        println!("[+] Sync complete.");
                        let _ = fsm.transition_to(SyncEngineState::Ready, "Sync finished");
                    }
                    Err(_) => {
                        let _ = fsm.transition_to(SyncEngineState::Discovering, "Peer unreachable");
                    }
                }
            }
        }
        thread::sleep(interval);
    }
}
