use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Configuration structure
#[derive(Deserialize, Serialize, Debug, Clone)]
struct Config {
    peer_ip: String,
    port: u16,
    poll_interval: f32,
}

// Clipboard representations
#[derive(Clone)]
enum ClipboardData {
    Text(String),
    Image(Vec<u8>),
}

// Thread-safe state for tracking the last synchronized clipboard digest
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
        format!("{:x}", hasher.finalize())
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
            peer_ip: "192.168.1.100".to_string(),
            port: 9999,
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
            peer_ip: "192.168.1.100".to_string(),
            port: 9999,
            poll_interval: 1.0,
        }
    })
}

// Helper to determine if running under a Wayland session
fn is_wayland() -> bool {
    env::var("WAYLAND_DISPLAY").is_ok() 
        || env::var("XDG_SESSION_TYPE").unwrap_or_default().to_lowercase().contains("wayland")
}

// OS execution wrappers to query clipboard state
fn get_linux_clipboard(wayland: bool) -> Option<ClipboardData> {
    if wayland {
        // Query Wayland targets
        let list_types = Command::new("wl-paste")
            .arg("--list-types")
            .output();

        if let Ok(output) = list_types {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("image/png") {
                let img_out = Command::new("wl-paste").arg("-t").arg("image/png").output();
                if let Ok(res) = img_out {
                    if res.status.success() && !res.stdout.is_empty() {
                        return Some(ClipboardData::Image(res.stdout));
                    }
                }
            }
        }

        // Fallback to text
        let text_out = Command::new("wl-paste").arg("-t").arg("text/plain").output();
        if let Ok(res) = text_out {
            if res.status.success() {
                return Some(ClipboardData::Text(String::from_utf8_lossy(&res.stdout).into_owned()));
            }
        }
        // General fallback
        let gen_out = Command::new("wl-paste").output();
        if let Ok(res) = gen_out {
            if res.status.success() {
                return Some(ClipboardData::Text(String::from_utf8_lossy(&res.stdout).into_owned()));
            }
        }
    } else {
        // X11 Clipboard targets
        let list_types = Command::new("xclip")
            .args(["-selection", "clipboard", "-o", "-t", "TARGETS"])
            .output();

        if let Ok(output) = list_types {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("image/png") {
                let img_out = Command::new("xclip")
                    .args(["-selection", "clipboard", "-t", "image/png", "-o"])
                    .output();
                if let Ok(res) = img_out {
                    if res.status.success() && !res.stdout.is_empty() {
                        return Some(ClipboardData::Image(res.stdout));
                    }
                }
            }

            // Text selections
            let target = if stdout.contains("UTF8_STRING") { "UTF8_STRING" } else { "STRING" };
            let text_out = Command::new("xclip")
                .args(["-selection", "clipboard", "-t", target, "-o"])
                .output();
            if let Ok(res) = text_out {
                if res.status.success() {
                    return Some(ClipboardData::Text(String::from_utf8_lossy(&res.stdout).into_owned()));
                }
            }
        }
    }
    None
}

// OS execution wrapper to update OS clipboard
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

    let mut process = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .expect("Failed to execute clipboard copy command");

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

// Outgoing client network transmitter
fn send_to_android(peer_ip: &str, port: u16, data: &ClipboardData) -> io::Result<()> {
    let (packet_type, payload) = match data {
        ClipboardData::Text(text) => (0u8, text.as_bytes().to_vec()),
        ClipboardData::Image(bytes) => (1u8, bytes.clone()),
    };

    let length = payload.len() as u32;
    let mut header = [0u8; 5];
    header[0] = packet_type;
    header[1..5].copy_from_slice(&length.to_be_bytes());

    let address = format!("{}:{}", peer_ip, port);
    let addr: std::net::SocketAddr = address
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;

    stream.write_all(&header)?;
    stream.write_all(&payload)?;
    Ok(())
}

// Local server receiver thread loop
fn run_server(port: u16, wayland: bool, state: Arc<Mutex<ClipboardState>>) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).expect("Could not bind TCP port");
    println!("[+] Rust TCP Server listening on port {}...", port);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state_clone = Arc::clone(&state);
                thread::spawn(move || {
                    let mut header = [0u8; 5];
                    if stream.read_exact(&mut header).is_err() {
                        return;
                    }

                    let packet_type = header[0];
                    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

                    // Enforce maximum payload size (25 MB) to prevent OOM panic DoS
                    const MAX_PAYLOAD_SIZE: usize = 25 * 1024 * 1024;
                    if length > MAX_PAYLOAD_SIZE {
                        eprintln!("[-] Connection rejected: payload size ({} bytes) exceeds limit (25MB)", length);
                        return;
                    }

                    let mut payload = vec![0u8; length];
                    if stream.read_exact(&mut payload).is_err() {
                        return;
                    }

                    // Hash check
                    let mut hasher = Sha256::new();
                    hasher.update(&payload);
                    let hash = format!("{:x}", hasher.finalize());

                    {
                        let mut guard = state_clone.lock().unwrap();
                        guard.update_received(hash);
                    }

                    let data = if packet_type == 0 {
                        let text = String::from_utf8_lossy(&payload).into_owned();
                        println!("[+] Received text from {}: {}...", stream.peer_addr().unwrap().ip(), &text[..std::cmp::min(30, text.len())]);
                        ClipboardData::Text(text)
                    } else {
                        println!("[+] Received image from {} ({} bytes)...", stream.peer_addr().unwrap().ip(), payload.len());
                        ClipboardData::Image(payload)
                    };

                    set_linux_clipboard(wayland, &data);
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

    // Verify dependencies
    let dep_check = if wayland { "wl-copy" } else { "xclip" };
    let output = Command::new("which").arg(dep_check).output();
    if output.is_err() || !output.unwrap().status.success() {
        eprintln!("[-] Missing dependency: '{}'. Please install it on your Linux system.", dep_check);
        std::process::exit(1);
    }

    let state = Arc::new(Mutex::new(ClipboardState::new()));

    // Populate initial hash from existing clipboard
    if let Some(init_data) = get_linux_clipboard(wayland) {
        let hash = ClipboardState::calculate_hash(&init_data);
        state.lock().unwrap().update_received(hash);
    }

    // Start background receiver server
    let server_state = Arc::clone(&state);
    let server_port = config.port;
    thread::spawn(move || {
        run_server(server_port, wayland, server_state);
    });

    // Main clipboard monitoring loop
    let interval = Duration::from_secs_f32(config.poll_interval);
    println!("[+] Clipboard Monitor started. Polling every {}s...", config.poll_interval);

    loop {
        if let Some(data) = get_linux_clipboard(wayland) {
            let hash = ClipboardState::calculate_hash(&data);
            let should_send = {
                let mut guard = state.lock().unwrap();
                guard.check_and_update_sent(hash)
            };

            if should_send {
                println!("[*] Local change detected. Syncing to Android ({}:{})...", config.peer_ip, config.port);
                match send_to_android(&config.peer_ip, config.port, &data) {
                    Ok(_) => println!("[+] Sync complete."),
                    Err(_) => {} // Silent network errors
                }
            }
        }
        thread::sleep(interval);
    }
}
