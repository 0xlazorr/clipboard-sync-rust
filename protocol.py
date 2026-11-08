"""
Secure Clipboard Sync Protocol & State Machine Engine
Enforces explicit typed FSMs, authenticated encryption, and privacy.
"""

import enum
import hashlib
import hmac
import os
import struct
import time
from typing import Optional, Tuple, Dict, Any

PROTOCOL_MAGIC = b"CS02"
PROTOCOL_VERSION = 2
MAX_PAYLOAD_SIZE = 25 * 1024 * 1024  # 25 MB limit to prevent memory exhaustion DoS
REPLAY_WINDOW_SECONDS = 60  # Maximum clock drift / replay window

# Packet Types
PKT_TEXT = 0
PKT_IMAGE = 1
PKT_DISCOVERY = 2
PKT_DISCOVERY_ACK = 3
PKT_PING = 4
PKT_PONG = 5


class SyncEngineState(enum.Enum):
    UNINITIALIZED = "UNINITIALIZED"
    DISCOVERING = "DISCOVERING"
    READY = "READY"
    TRANSFERRING = "TRANSFERRING"
    ERROR = "ERROR"
    STOPPED = "STOPPED"


class ClipboardItemState(enum.Enum):
    IDLE = "IDLE"
    CAPTURED = "CAPTURED"
    ENCRYPTED = "ENCRYPTED"
    TRANSMITTED = "TRANSMITTED"
    RECEIVED = "RECEIVED"
    AUTHENTICATED = "AUTHENTICATED"
    DECRYPTED = "DECRYPTED"
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"


class StateTransitionError(Exception):
    """Raised when an illegal FSM state transition is attempted."""
    pass


class SyncEngineFSM:
    """Explicit Finite State Machine governing the sync daemon lifecycle."""

    _VALID_TRANSITIONS = {
        SyncEngineState.UNINITIALIZED: {
            SyncEngineState.DISCOVERING,
            SyncEngineState.READY,
            SyncEngineState.STOPPED,
        },
        SyncEngineState.DISCOVERING: {
            SyncEngineState.READY,
            SyncEngineState.ERROR,
            SyncEngineState.STOPPED,
        },
        SyncEngineState.READY: {
            SyncEngineState.TRANSFERRING,
            SyncEngineState.DISCOVERING,
            SyncEngineState.ERROR,
            SyncEngineState.STOPPED,
        },
        SyncEngineState.TRANSFERRING: {
            SyncEngineState.READY,
            SyncEngineState.DISCOVERING,
            SyncEngineState.ERROR,
            SyncEngineState.STOPPED,
        },
        SyncEngineState.ERROR: {
            SyncEngineState.DISCOVERING,
            SyncEngineState.READY,
            SyncEngineState.STOPPED,
        },
        SyncEngineState.STOPPED: {
            SyncEngineState.UNINITIALIZED,
        },
    }

    def __init__(self, initial_state: SyncEngineState = SyncEngineState.UNINITIALIZED):
        self._state = initial_state

    @property
    def current_state(self) -> SyncEngineState:
        return self._state

    def transition_to(self, new_state: SyncEngineState, reason: str = "") -> None:
        if new_state == self._state:
            return
        allowed = self._VALID_TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            raise StateTransitionError(
                f"Illegal transition from {self._state.value} to {new_state.value} (reason: {reason})"
            )
        self._state = new_state


def derive_master_key(secret: str) -> bytes:
    """Derive a 256-bit symmetric master key from a pre-shared secret key using PBKDF2-HMAC-SHA256."""
    salt = b"ClipboardSyncSalt_v2_PrivacyGuard"
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 10000, 32)


def xor_keystream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    Symmetric keystream CTR cipher using HMAC-SHA256 block expansion.
    Produces identical ciphertext/plaintext under XOR.
    """
    out = bytearray(len(data))
    block_idx = 0
    for offset in range(0, len(data), 32):
        block_key = hmac.new(key, nonce + struct.pack(">Q", block_idx), hashlib.sha256).digest()
        chunk_len = min(32, len(data) - offset)
        for i in range(chunk_len):
            out[offset + i] = data[offset + i] ^ block_key[i]
        block_idx += 1
    result = bytes(out)
    # Zeroize intermediate mutable bytearray
    for i in range(len(out)):
        out[i] = 0
    return result


def pack_packet(key: bytes, pkt_type: int, payload: bytes) -> bytes:
    """
    Create an authenticated, encrypted packet:
    [0..4]   Magic: b"CS02"
    [4..5]   Pkt Type (1 byte)
    [5..13]  Timestamp (8 bytes big-endian)
    [13..17] Payload Length (4 bytes big-endian)
    [17..33] Nonce (16 bytes random)
    [33..65] HMAC-SHA256 Tag (32 bytes)
    [65..]   Encrypted Payload
    """
    ts = int(time.time())
    nonce = os.urandom(16)
    encrypted = xor_keystream(key, nonce, payload)
    length = len(encrypted)

    header = PROTOCOL_MAGIC + struct.pack("!BQI", pkt_type, ts, length) + nonce
    tag = hmac.new(key, header + encrypted, hashlib.sha256).digest()
    return header + tag + encrypted


def unpack_packet(key: bytes, raw: bytes) -> Tuple[Optional[int], Optional[bytes], Optional[str]]:
    """
    Validate, authenticate, and decrypt a packet.
    Returns (pkt_type, decrypted_payload, error_string).
    """
    min_len = 4 + 1 + 8 + 4 + 16 + 32  # 65 bytes header + tag
    if len(raw) < min_len:
        return None, None, f"Packet too short ({len(raw)} bytes)"

    magic = raw[:4]
    if magic != PROTOCOL_MAGIC:
        return None, None, f"Invalid protocol magic: {magic!r}"

    pkt_type, ts, length = struct.unpack("!BQI", raw[4:17])
    nonce = raw[17:33]
    tag = raw[33:65]
    encrypted = raw[65:65 + length]

    if len(encrypted) != length:
        return None, None, f"Payload length mismatch: expected {length}, got {len(encrypted)}"

    # Replay protection: check timestamp against window
    now = time.time()
    if abs(now - ts) > REPLAY_WINDOW_SECONDS:
        return None, None, f"Expired or future timestamp: delta={abs(now - ts):.1f}s"

    # Authenticate via constant-time comparison
    header = magic + struct.pack("!BQI", pkt_type, ts, length) + nonce
    expected_tag = hmac.new(key, header + encrypted, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        return None, None, "Invalid HMAC authentication tag (unauthorized peer or tampered payload)"

    decrypted = xor_keystream(key, nonce, encrypted)
    return pkt_type, decrypted, None


def sanitize_hash(data: bytes) -> str:
    """Return a short SHA-256 fingerprint for safe, privacy-preserving logging."""
    return hashlib.sha256(data).hexdigest()[:12]
