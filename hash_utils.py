"""
Secure utility functions for File Integrity Checker (FIC)

- SHA-256 hashing (chunked) with robust error handling
- Record save/load in JSON with HMAC signatures (tamper detection)
- Atomic writes for JSON files
- History append with signing
- Key generation & safe storage for HMAC key
"""

import os
import json
import hashlib
import hmac
import secrets
import tempfile
from datetime import datetime
from typing import Tuple, Dict, Any

RECORDS_FILE = "integrity_records.json"
HISTORY_FILE = "history.json"
KEY_FILE = ".fic_key"                # HMAC key (should be protected)
SIG_EXT = ".sig"                     # sidecar signature files

# File permission modes (owner read/write only)
_FILE_PERMISSIONS = 0o600


def _ensure_key():
    """Ensure HMAC key exists; create with secure permissions if missing."""
    if not os.path.exists(KEY_FILE):
        key = secrets.token_bytes(32)
        # Write atomically and set secure permissions
        fd, tmp = tempfile.mkstemp(dir='.', prefix='.fic_key_tmp_')
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(key)
            os.replace(tmp, KEY_FILE)
            try:
                os.chmod(KEY_FILE, _FILE_PERMISSIONS)
            except Exception:
                # best-effort; on some OSs this might fail (e.g., Windows)
                pass
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass


def _load_key() -> bytes:
    _ensure_key()
    try:
        with open(KEY_FILE, "rb") as f:
            return f.read()
    except Exception:
        # fallback: regenerate key (if unreadable)
        _ensure_key()
        with open(KEY_FILE, "rb") as f:
            return f.read()


def _hmac_of_bytes(key: bytes, data_bytes: bytes) -> str:
    return hmac.new(key, data_bytes, hashlib.sha256).hexdigest()


def _sign_json_file(path: str):
    """Write signature sidecar for given JSON file."""
    key = _load_key()
    with open(path, "rb") as f:
        payload = f.read()
    sig = _hmac_of_bytes(key, payload)
    with open(path + SIG_EXT, "w", encoding="utf-8") as sf:
        json.dump({"hmac": sig}, sf)


def _verify_json_signature(path: str) -> bool:
    """Return True if signature sidecar matches file contents. If no sig file exists, treat as mismatch."""
    key = _load_key()
    try:
        with open(path, "rb") as f:
            payload = f.read()
    except Exception:
        return False
    sig_path = path + SIG_EXT
    if not os.path.exists(sig_path):
        return False
    try:
        with open(sig_path, "r", encoding="utf-8") as sf:
            obj = json.load(sf)
        expected = obj.get("hmac", "")
    except Exception:
        return False
    actual = _hmac_of_bytes(key, payload)
    return hmac.compare_digest(expected, actual)


def _atomic_write_json(path: str, obj: Any):
    """Write JSON to path atomically and sign it."""
    fd, tmp = tempfile.mkstemp(dir='.', prefix=os.path.basename(path) + ".tmp.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, path)
        try:
            os.chmod(path, _FILE_PERMISSIONS)
        except Exception:
            pass
        # generate signature sidecar
        _sign_json_file(path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def ensure_files():
    """Create default JSON files if not present (with signatures)."""
    _ensure_key()
    if not os.path.exists(RECORDS_FILE):
        _atomic_write_json(RECORDS_FILE, {})
    elif not _verify_json_signature(RECORDS_FILE):
        # quarantine corrupted file
        quarantine = RECORDS_FILE + ".corrupt"
        try:
            os.replace(RECORDS_FILE, quarantine)
        except Exception:
            pass
        _atomic_write_json(RECORDS_FILE, {})
    if not os.path.exists(HISTORY_FILE):
        _atomic_write_json(HISTORY_FILE, [])
    elif not _verify_json_signature(HISTORY_FILE):
        quarantine = HISTORY_FILE + ".corrupt"
        try:
            os.replace(HISTORY_FILE, quarantine)
        except Exception:
            pass
        _atomic_write_json(HISTORY_FILE, [])


def sha256_hash(path: str, chunk_size: int = 65536) -> str:
    """Return SHA-256 hex digest for file at path (chunked). Raises IOError on failure."""
    h = hashlib.sha256()
    abs_path = os.path.abspath(path)
    with open(abs_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_records() -> Dict[str, Dict[str, Any]]:
    """Load records JSON if signature verifies; otherwise return empty dict."""
    ensure_files()
    if not _verify_json_signature(RECORDS_FILE):
        # Quarantine and return empty to avoid trusting tampered records
        try:
            os.replace(RECORDS_FILE, RECORDS_FILE + ".corrupt")
        except Exception:
            pass
        _atomic_write_json(RECORDS_FILE, {})
        return {}
    try:
        with open(RECORDS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_record(file_path: str, file_hash: str):
    """Save or update a record for file_path with its hash and timestamp (atomic + signed)."""
    ensure_files()
    records = load_records()
    abs_path = os.path.abspath(file_path)
    entry = {
        "hash": file_hash,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "size": os.path.getsize(abs_path) if os.path.exists(abs_path) else -1
    }
    records[abs_path] = entry
    _atomic_write_json(RECORDS_FILE, records)


def append_history(action: str, file_path: str, result: str):
    """Append an entry to history (keeps up to 200 entries) with signing."""
    ensure_files()
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            hist = json.load(f)
    except Exception:
        hist = []
    entry = {
        "action": action,
        "file": os.path.basename(file_path),
        "path": os.path.abspath(file_path),
        "result": result,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    hist.insert(0, entry)
    hist = hist[:200]
    _atomic_write_json(HISTORY_FILE, hist)


def clear_history():
    """Securely clear history (use atomic write + signature)."""
    ensure_files()
    _atomic_write_json(HISTORY_FILE, [])


def verify_records_signature() -> bool:
    """Public helper; returns whether records file signature verifies."""
    return _verify_json_signature(RECORDS_FILE)


def verify_history_signature() -> bool:
    return _verify_json_signature(HISTORY_FILE)
