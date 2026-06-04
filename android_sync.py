#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import struct
import hashlib
import subprocess
import threading
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def load_config():
    default_config = {
        "peer_ip": "192.168.1.50",  # Linux PC IP
        "port": 9999,
        "poll_interval": 1.5       # Slightly longer poll interval for phone battery conservation
    }
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump(default_config, f, indent=4)
        return default_config
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Error reading config.json: {e}. Using defaults.")
        return default_config

# Helper to verify Termux API commands
def check_dependencies():
    dependencies = ["termux-clipboard-get", "termux-clipboard-set", "termux-notification"]
    missing = []
    for dep in dependencies:
        if subprocess.run(["which", dep], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            missing.append(dep)
    if missing:
        print(f"[-] Missing Termux commands: {', '.join(missing)}")
        print("[-] Please run 'pkg install termux-api' in Termux and ensure the Termux:API app is installed from F-Droid.")
        sys.exit(1)

# Clipboard State Manager
class ClipboardState:
    def __init__(self):
        self.last_hash = None
        self.lock = threading.Lock()

    def get_hash(self, data):
        if isinstance(data, str):
            return hashlib.sha256(data.encode('utf-8')).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def update_received(self, data_hash):
        with self.lock:
            self.last_hash = data_hash

    def check_and_update_sent(self, data_hash):
        with self.lock:
            if self.last_hash == data_hash:
                return False
            self.last_hash = data_hash
            return True

state_manager = ClipboardState()

# Termux Notification Helper
def show_notification(title, content, action_cmd=None, button_label=None, button_action=None):
    cmd = ["termux-notification", "-t", title, "-c", content, "--id", "clipboard_sync_notif"]
    if action_cmd:
        cmd += ["--action", action_cmd]
    if button_label and button_action:
        cmd += ["--button1", button_label, "--button1-action", button_action]
    subprocess.run(cmd)

# Read/Write Android Clipboard via Termux API
def get_android_clipboard():
    try:
        # Run termux-clipboard-get
        res = subprocess.run(["termux-clipboard-get"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2.0)
        if res.returncode == 0:
            text = res.stdout.decode('utf-8', errors='ignore')
            # Termux clipboard returns empty string if no clipboard access or empty
            return "text", text
    except Exception as e:
        print(f"[-] Error reading Android clipboard: {e}")
    return None, None

def set_android_clipboard(clip_type, data):
    if clip_type == "text":
        try:
            proc = subprocess.Popen(["termux-clipboard-set"], stdin=subprocess.PIPE)
            proc.communicate(input=data.encode('utf-8'))
            
            # Show a brief notification confirming receipt
            short_text = data if len(data) < 35 else data[:32] + "..."
            show_notification("Clipboard Synced (Text)", f"Copied: {short_text}")
            print(f"[+] Synced and copied text: {short_text}")
        except Exception as e:
            print(f"[-] Failed to set Android clipboard: {e}")
            show_notification("Sync Error", "Could not write to Android clipboard directly.")
            
    elif clip_type == "image":
        # Save image to storage and trigger notification
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        sync_dir = "/sdcard/Pictures/Clipboard_Sync"
        filename = f"{sync_dir}/sync_{now}.png"
        
        try:
            # Ensure folder exists
            os.makedirs(sync_dir, exist_ok=True)
            with open(filename, "wb") as f:
                f.write(data)
            
            # Notification with action to view the image
            show_notification(
                title="Clipboard Synced (Image)",
                content=f"Saved to Pictures/Clipboard_Sync/sync_{now}.png",
                action_cmd=f"termux-open {filename}"
            )
            print(f"[+] Received image saved to: {filename}")
        except Exception as e:
            print(f"[-] Failed to save image to SD card: {e}")
            # Fallback to Termux home directory if permissions missing
            fallback_path = os.path.expanduser(f"~/sync_{now}.png")
            try:
                with open(fallback_path, "wb") as f:
                    f.write(data)
                show_notification(
                    title="Clipboard Synced (Image - Home)",
                    content="Saved in Termux home folder (No storage permission)",
                    action_cmd=f"termux-open {fallback_path}"
                )
                print(f"[+] Fallback saved to: {fallback_path}")
            except Exception as e2:
                print(f"[-] Fallback save also failed: {e2}")

# Server Socket (Receiving from Linux)
def run_server(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        sock.listen(5)
        print(f"[+] Android TCP Server listening on {host}:{port}...")
    except Exception as e:
        print(f"[-] Failed to bind Android server: {e}")
        return

    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_incoming_connection, args=(conn, addr), daemon=True).start()
        except Exception:
            break

def handle_incoming_connection(conn, addr):
    try:
        conn.settimeout(5.0)
        header = conn.recv(5)
        if not header or len(header) < 5:
            return
        packet_type, length = struct.unpack("!BI", header)
        
        # Limit max payload size to 25 MB to prevent memory exhaustion attacks
        MAX_PAYLOAD_SIZE = 25 * 1024 * 1024
        if length > MAX_PAYLOAD_SIZE:
            print(f"[-] Connection rejected from {addr[0]}: payload size ({length} bytes) exceeds limit (25MB)")
            return

        payload = b""
        while len(payload) < length:
            chunk = conn.recv(min(length - len(payload), 4096))
            if not chunk:
                break
            payload += chunk
        
        if len(payload) == length:
            data_hash = state_manager.get_hash(payload)
            state_manager.update_received(data_hash)
            
            if packet_type == 0:
                text = payload.decode('utf-8', errors='ignore')
                set_android_clipboard("text", text)
            elif packet_type == 1:
                set_android_clipboard("image", payload)
    except Exception as e:
        print(f"[-] Error handling incoming Linux packet: {e}")
    finally:
        conn.close()

# Client Sender (Sending to Linux)
def send_to_linux(peer_ip, port, clip_type, data):
    packet_type = 0 if clip_type == "text" else 1
    payload = data.encode('utf-8') if clip_type == "text" else data
    length = len(payload)
    header = struct.pack("!BI", packet_type, length)
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect((peer_ip, port))
            s.sendall(header + payload)
            return True
    except Exception:
        # Ignore unreachable errors to avoid stdout clutter
        return False

# Monitor Loop
def run_monitor(peer_ip, port, poll_interval):
    # Initialize state with current clipboard content
    init_type, init_data = get_android_clipboard()
    if init_data:
        state_manager.last_hash = state_manager.get_hash(init_data)
        print("[+] Monitor initialized with existing Android clipboard.")

    while True:
        try:
            clip_type, data = get_android_clipboard()
            # If clipboard contains text (Termux API is text-only for reads)
            if data:
                data_hash = state_manager.get_hash(data)
                if state_manager.check_and_update_sent(data_hash):
                    print(f"[*] Android clipboard change detected. Syncing to Linux ({peer_ip})...")
                    success = send_to_linux(peer_ip, port, clip_type, data)
                    if success:
                        print("[+] Sync complete.")
                    else:
                        print("[-] Sync failed (Linux host offline or unreachable).")
        except Exception as e:
            print(f"[-] Error in Android monitor loop: {e}")
        time.sleep(poll_interval)

if __name__ == "__main__":
    check_dependencies()
    config = load_config()
    
    # Start receiver thread
    server_thread = threading.Thread(
        target=run_server,
        args=("0.0.0.0", config["port"]),
        daemon=True
    )
    server_thread.start()
    
    # Run clipboard sender in main thread
    run_monitor(
        peer_ip=config["peer_ip"],
        port=config["port"],
        poll_interval=config["poll_interval"]
    )
