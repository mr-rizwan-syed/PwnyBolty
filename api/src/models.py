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