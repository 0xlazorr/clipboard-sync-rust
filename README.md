# Secure Bi-Directional Clipboard Sync (Rust Edition)

A high-performance, lightweight Linux clipboard synchronization daemon in Rust paired with an Android Termux client.

---

## Features
* **Explicit Finite State Machines (FSM):** Engine lifecycles and clipboard synchronization states are formally tracked and validated (`SyncEngineFSM` and `ClipboardItemState`).
* **Authenticated Symmetric Transport (AEAD):** Keystream payload encryption and HMAC-SHA256 authenticated framing with dynamic 256-bit key derivation via PBKDF2.
* **Dynamic LAN Discovery:** Automatically pairs with the companion Android client without requiring static IP configuration.
* **Privacy by Design:** Zero clipboard text printed to standard output or terminal logs; sanitizes all diagnostics using truncated SHA-256 fingerprints.
* **Wayland & X11 Support:** Detects session display server and handles clipboard synchronization cleanly.

---

## Configuration & Usage

1. Edit `config.json`:
```json
{
    "secret_key": "REPLACE_WITH_YOUR_SHARED_SECRET_KEY",
    "peer_ip": "192.168.1.100",
    "port": 9999,
    "discovery_port": 9998,
    "enable_discovery": true,
    "poll_interval": 1.0
}
```

2. Build and run:
```bash
cargo build --release
./target/release/clipboard-sync
```

3. Configure Android companion in Termux using `android_sync.py` and `protocol.py`.
