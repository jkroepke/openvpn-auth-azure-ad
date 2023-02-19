from typing import Dict, TypedDict, Optional


class ClientDataType(TypedDict):
    env: Dict[str, str]
    reason: str
    kid: int
    cid: int
    state_id: Optional[str]
