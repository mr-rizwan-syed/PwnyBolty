"""
Global persistent store for Bolthole C2 configuration and outbound SSH keypair.

The outbound keypair (boltcon → C2 auth) is shared across all builds so the C2
server only needs one authorized_keys entry regardless of how many packages are
generated.  The keypair lives in DATA_DIR; it is auto-generated on first use and
can be rotated on demand via the /api/bolthole/c2 POST endpoint.
"""
import json
import os
import subprocess
import tempfile
from typing import Optional

DATA_DIR = os.environ.get("BOLTHOLE_DATA_DIR", "/app/data")
_CONFIG_FILE = os.path.join(DATA_DIR, "bolthole_config.json")
_PRIVKEY_FILE = os.path.join(DATA_DIR, "bolthole_outbound_key")
_PUBKEY_FILE  = os.path.join(DATA_DIR, "bolthole_outbound_key.pub")

_DEFAULT_CONFIG = {
    "ssh_host":          "",
    "ssh_user":          "",
    "ports":             "443,80,22,31337",
    "tunnel_port_range": "31332-31345",
    "socks_port":        1080,
    "startup_delay":     5,
    "reconnect_delay":   30,
}


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


# ── Config ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not os.path.exists(_CONFIG_FILE):
        return dict(_DEFAULT_CONFIG)
    with open(_CONFIG_FILE) as f:
        data = json.load(f)
    merged = dict(_DEFAULT_CONFIG)
    merged.update(data)
    return merged


def save_config(config: dict):
    _ensure_data_dir()
    with open(_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# ── Keypair ───────────────────────────────────────────────────────────────────

def load_keypair() -> tuple[Optional[str], Optional[str]]:
    """Return (private_key, public_key) strings or (None, None) if not yet generated."""
    if not os.path.exists(_PRIVKEY_FILE) or not os.path.exists(_PUBKEY_FILE):
        return None, None
    with open(_PRIVKEY_FILE) as f:
        private_key = f.read()
    with open(_PUBKEY_FILE) as f:
        public_key = f.read()
    return private_key, public_key


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh ECDSA-256 keypair, persist it, return (private, public)."""
    _ensure_data_dir()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix="_bh_global_key", delete=False) as tmp:
            tmp_path = tmp.name
        os.unlink(tmp_path)
        subprocess.run(
            ["ssh-keygen", "-t", "ecdsa", "-b", "256", "-f", tmp_path, "-N", ""],
            check=True, capture_output=True,
        )
        with open(tmp_path) as f:
            private_key = f.read()
        with open(tmp_path + ".pub") as f:
            public_key = f.read()
    finally:
        for p in [tmp_path, (tmp_path or "") + ".pub"]:
            if p and os.path.exists(p):
                os.unlink(p)

    with open(_PRIVKEY_FILE, "w", newline="\n") as f:
        f.write(private_key)
    os.chmod(_PRIVKEY_FILE, 0o600)
    with open(_PUBKEY_FILE, "w") as f:
        f.write(public_key)

    return private_key, public_key


def get_or_generate_keypair() -> tuple[str, str]:
    """Return the stored keypair, generating one on first call."""
    priv, pub = load_keypair()
    if priv and pub:
        return priv, pub
    return generate_keypair()


def get_fingerprint(public_key: str) -> Optional[str]:
    """Return the SHA256 fingerprint of a public key string, or None on failure."""
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            suffix="_bh_pubkey", mode="w", delete=False
        ) as tmp:
            tmp.write(public_key)
            tmp_path = tmp.name
        result = subprocess.run(
            ["ssh-keygen", "-l", "-f", tmp_path],
            capture_output=True, text=True, check=True,
        )
        parts = result.stdout.strip().split()
        return parts[1] if len(parts) >= 2 else result.stdout.strip()
    except Exception:  # pylint: disable=broad-except
        return None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
