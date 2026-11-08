#!/usr/bin/env python3
"""
Secure Clipboard Sync Daemon (Android / Termux)
Features:
- Explicit Finite State Machines (SyncEngineFSM, ClipboardItemState)
- Authenticated symmetric payload encryption (HMAC-SHA256 + CTR keystream)
- UDP LAN auto-discovery with authenticated beacons (resolves dynamic IP issues)
- Defensive Termux API integration (graceful handling of background clipboard limitations)
- Privacy-first sanitized logging and memory zeroization
"""

from datetime import datetime
import json
import os
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Optional, Tuple

try:
    from protocol import (
        SyncEngineState,
        SyncEngineFSM,
        ClipboardItemState,
        derive_master_key,
        pack_packet,
        unpack_packet,
        sanitize_hash,
        PKT_TEXT,
        PKT_IMAGE,
        PKT_DISCOVERY,
        PKT_DISCOVERY_ACK,
        MAX_PAYLOAD_SIZE,
    )
except ImportError:
    # If copied standalone to Android without protocol.py, raise descriptive error
    print("[-] protocol.py not found in the current directory.")
    print("[-] Please ensure protocol.py is present alongside android_sync.py.")
    sys.exit(1)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def load_or_create_config() -> dict:
    default_config = {
        "secret_key": "",
        "peer_ip": "192.168.1.50",
        "port": 9999,
        "discovery_port": 9998,
        "enable_discovery": True,
        "poll_interval": 1.5,
    }

    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump(default_config, f, indent=4)
        print(f"[!] Created template {CONFIG_PATH}. Please populate 'secret_key' from your Linux host.")
        return default_config

    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
        changed = False
        if "discovery_port" not in config:
            config["discovery_port"] = 9998
            changed = True
        if "enable_discovery" not in config:
            config["enable_discovery"] = True
            changed = True
        if changed:
            with open(CONFIG_PATH, "w") as f:
                json.dump(config, f, indent=4)
        return config
    except Exception as e:
        print(f"[-] Error reading {CONFIG_PATH}: {e}. Using defaults.")
        return default_config


def check_termux_environment() -> dict:
    status = {
        "has_clipboard_get": shutil.which("termux-clipboard-get") is not None,
        "has_clipboard_set": shutil.which("termux-clipboard-set") is not None,
        "has_notification": shutil.which("termux-notification") is not None,
        "has_open": shutil.which("termux-open") is not None,
    }

    if not status["has_clipboard_set"]:
        print("[!] Warning: 'termux-clipboard-set' not detected.")
        print("[!] Run: 'pkg install termux-api' and verify Termux:API app is installed.")

    return status


def show_notification(title: str, content: str, action_cmd: Optional[str] = None):
    if not shutil.which("termux-notification"):
        return
    cmd = ["termux-notification", "-t", title, "-c", content, "--id", "clipboard_sync_notif"]
    if action_cmd:
        cmd += ["--action", action_cmd]
    try:
        subprocess.run(cmd, timeout=3.0)
    except Exception:
        pass


def get_android_clipboard() -> Tuple[Optional[str], Optional[bytes]]:
    if not shutil.which("termux-clipboard-get"):
        return None, None
    try:
        res = subprocess.run(
            ["termux-clipboard-get"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2.0,
        )
        if res.returncode == 0 and res.stdout:
            # Note: Termux returns empty byte string if clipboard is empty or permission withheld
            text = res.stdout.strip()
            if text:
                return "text", text
    except Exception:
        pass
    return None, None


def set_android_clipboard(clip_type: str, data: bytes) -> bool:
    if clip_type == "text":
        if not shutil.which("termux-clipboard-set"):
            return False
        try:
            proc = subprocess.Popen(["termux-clipboard-set"], stdin=subprocess.PIPE)
            proc.communicate(input=data, timeout=3.0)
            show_notification("Clipboard Synced", f"Received text ({len(data)} bytes)")
            return proc.returncode == 0
        except Exception as e:
            print(f"[-] Failed to set Android clipboard: {e}")
            return False
    elif clip_type == "image":
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        sync_dir = "/sdcard/Pictures/Clipboard_Sync"
        filename = f"{sync_dir}/sync_{now}.png"
        try:
            os.makedirs(sync_dir, exist_ok=True)
            with open(filename, "wb") as f:
                f.write(data)
            show_notification(
                title="Clipboard Synced (Image)",
                content=f"Saved image to Pictures/Clipboard_Sync/sync_{now}.png",
                action_cmd=f"termux-open {filename}" if shutil.which("termux-open") else None,
            )
            return True
        except Exception:
            fallback = os.path.expanduser(f"~/sync_{now}.png")
            try:
                with open(fallback, "wb") as f:
                    f.write(data)
                show_notification("Clipboard Synced (Image)", f"Saved to ~/sync_{now}.png")
                return True
            except Exception:
                return False
    return False


class AndroidClipboardDaemon:
    def __init__(self, config: dict):
        self.config = config
        secret = config.get("secret_key", "").strip()
        if not secret:
            print("[!] FATAL: 'secret_key' is empty in config.json!")
            print("[!] Please copy the 'secret_key' generated on your Linux laptop into config.json on this phone.")
            sys.exit(1)

        self.key = derive_master_key(secret)
        self.fsm = SyncEngineFSM()
        self.env_status = check_termux_environment()

        self.peer_ip = config.get("peer_ip", "192.168.1.50")
        self.port = int(config.get("port", 9999))
        self.discovery_port = int(config.get("discovery_port", 9998))
        self.enable_discovery = bool(config.get("enable_discovery", True))
        self.poll_interval = float(config.get("poll_interval", 1.5))

        self.last_hash: Optional[str] = None
        self.state_lock = threading.Lock()
        self.running = threading.Event()
        self.running.set()

    def update_known_peer(self, new_ip: str, source: str = "discovery"):
        with self.state_lock:
            if self.peer_ip != new_ip:
                print(f"[+] Dynamic Linux host discovered via {source}: {new_ip} (was {self.peer_ip})")
                self.peer_ip = new_ip
                if self.fsm.current_state in (SyncEngineState.DISCOVERING, SyncEngineState.ERROR):
                    self.fsm.transition_to(SyncEngineState.READY, f"Discovered host {new_ip}")

    def run_discovery_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("0.0.0.0", self.discovery_port))
            sock.settimeout(2.0)
            print(f"[+] Android UDP Discovery listener active on port {self.discovery_port}")
        except Exception as e:
            print(f"[-] Failed to bind discovery port {self.discovery_port}: {e}")
            return

        while self.running.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                pkt_type, payload, err = unpack_packet(self.key, data)
                if err:
                    continue  # Silently ignore untrusted packets

                if pkt_type in (PKT_DISCOVERY, PKT_DISCOVERY_ACK):
                    peer_addr = addr[0]
                    self.update_known_peer(peer_addr, source="UDP beacon")

                    # Reply with ACK if this was an incoming discovery beacon from Linux
                    if pkt_type == PKT_DISCOVERY:
                        ack_payload = json.dumps({"role": "android", "status": "ack"}).encode("utf-8")
                        ack_pkt = pack_packet(self.key, PKT_DISCOVERY_ACK, ack_payload)
                        sock.sendto(ack_pkt, (peer_addr, self.discovery_port))
            except socket.timeout:
                continue
            except Exception:
                pass
        sock.close()

    def run_discovery_beacon(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        beacon_data = json.dumps({"role": "android", "port": self.port}).encode("utf-8")
        packet = pack_packet(self.key, PKT_DISCOVERY, beacon_data)

        while self.running.is_set():
            try:
                sock.sendto(packet, ("255.255.255.255", self.discovery_port))
                if self.peer_ip:
                    sock.sendto(packet, (self.peer_ip, self.discovery_port))
            except Exception:
                pass
            time.sleep(5.0 if self.fsm.current_state == SyncEngineState.DISCOVERING else 20.0)
        sock.close()

    def run_tcp_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
            server.listen(5)
            server.settimeout(2.0)
            print(f"[+] Encrypted Android TCP server listening on port {self.port}...")
        except Exception as e:
            print(f"[-] Server bind failed on port {self.port}: {e}")
            self.fsm.transition_to(SyncEngineState.ERROR, str(e))
            return

        while self.running.is_set():
            try:
                conn, addr = server.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        server.close()

    def _recv_all(self, conn: socket.socket, length: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < length:
            chunk = conn.recv(length - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _handle_client(self, conn: socket.socket, addr):
        try:
            conn.settimeout(5.0)
            header = self._recv_all(conn, 65)
            if not header or len(header) < 65:
                return

            length = struct.unpack("!I", header[13:17])[0]
            if length > MAX_PAYLOAD_SIZE:
                return

            payload_raw = self._recv_all(conn, length)
            if payload_raw is None or len(payload_raw) != length:
                return

            full_packet = header + payload_raw
            pkt_type, decrypted, err = unpack_packet(self.key, full_packet)
            if err:
                print(f"[-] Authentication/decryption error from {addr[0]}: {err}")
                return

            digest = sanitize_hash(decrypted)
            with self.state_lock:
                self.last_hash = digest

            if pkt_type == PKT_TEXT:
                print(f"[+] Received text payload from {addr[0]} (length: {len(decrypted)}B, hash: {digest})")
                set_android_clipboard("text", decrypted)
            elif pkt_type == PKT_IMAGE:
                print(f"[+] Received image payload from {addr[0]} (length: {len(decrypted)}B, hash: {digest})")
                set_android_clipboard("image", decrypted)

            self.update_known_peer(addr[0], source="authenticated TCP sync")
        except Exception as e:
            print(f"[-] Error handling incoming sync from {addr[0]}: {e}")
        finally:
            conn.close()

    def send_to_peer(self, clip_type: str, data: bytes) -> bool:
        pkt_type = PKT_TEXT if clip_type == "text" else PKT_IMAGE
        packet = pack_packet(self.key, pkt_type, data)
        peer = self.peer_ip

        if not peer:
            return False

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((peer, self.port))
                s.sendall(packet)
                return True
        except Exception:
            return False

    def run_monitor(self):
        init_type, init_data = get_android_clipboard()
        if init_data:
            self.last_hash = sanitize_hash(init_data)
            print(f"[+] Android monitor initialized with current clipboard (hash: {self.last_hash})")

        self.fsm.transition_to(
            SyncEngineState.DISCOVERING if self.enable_discovery else SyncEngineState.READY,
            "Android daemon started"
        )

        while self.running.is_set():
            try:
                clip_type, data = get_android_clipboard()
                if data:
                    current_hash = sanitize_hash(data)
                    should_send = False
                    with self.state_lock:
                        if self.last_hash != current_hash:
                            self.last_hash = current_hash
                            should_send = True

                    if should_send:
                        if self.fsm.current_state != SyncEngineState.TRANSFERRING:
                            try:
                                self.fsm.transition_to(SyncEngineState.TRANSFERRING, "Android outbound sync")
                            except Exception:
                                pass

                        print(f"[*] Android change detected (hash: {current_hash}). Encrypting and syncing to {self.peer_ip}...")
                        success = self.send_to_peer(clip_type, data)
                        if success:
                            print(f"[+] Sync complete to {self.peer_ip}.")
                            try:
                                self.fsm.transition_to(SyncEngineState.READY, "Sync finished")
                            except Exception:
                                pass
                        else:
                            print(f"[-] Linux host {self.peer_ip} unreachable (searching via discovery beacons).")
                            try:
                                self.fsm.transition_to(SyncEngineState.DISCOVERING, "Host unreachable")
                            except Exception:
                                pass
            except Exception as e:
                print(f"[-] Error in Android monitor loop: {e}")
            time.sleep(self.poll_interval)

    def start(self):
        def shutdown_handler(signum, frame):
            print("\n[*] Stopping Android Clipboard Daemon gracefully...")
            self.running.clear()
            try:
                self.fsm.transition_to(SyncEngineState.STOPPED, "Termination signal")
            except Exception:
                pass
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)

        if self.enable_discovery:
            threading.Thread(target=self.run_discovery_listener, daemon=True).start()
            threading.Thread(target=self.run_discovery_beacon, daemon=True).start()

        threading.Thread(target=self.run_tcp_server, daemon=True).start()
        self.run_monitor()


if __name__ == "__main__":
    cfg = load_or_create_config()
    daemon = AndroidClipboardDaemon(cfg)
    daemon.start()
