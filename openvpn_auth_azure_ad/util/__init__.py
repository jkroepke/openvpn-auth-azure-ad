import base64
import uuid

from typing import Optional


def b64encode_string(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


def is_authenticated(result: dict) -> bool:
    return "access_token" in result


def generated_id() -> str:
    return str(uuid.uuid4())


def format_error(result: dict) -> str:
    return result.get("error_description").splitlines()[0].strip()


def get_state_id(client: dict) -> Optional[str]:
    if "password" not in client["env"]:
        return None

    password = client["env"]["password"].split("::")
    if len(password) < 2:
        return None

    return password[1]


def get_auth_token(client: dict) -> Optional[str]:
    if "password" not in client["env"]:
        return None

    return client["env"]["password"]


def format_client_challenge(client: dict, challenge) -> str:
    username_b64 = b64encode_string(client["env"]["username"])
    return "CRV1:E,R:%s:%s:%s" % (client["state_id"], username_b64, challenge)
