import base64
from util import errors


def b64encode_string(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


def parse_client_data(data: str) -> dict:
    client = {
        'env': {},
        'reason': None,
        'cid': None,
        'kid': None,
    }

    for line in data.splitlines():
        if line.startswith(">CLIENT:CONNECT"):
            client_info = line.split(',')
            client['reason'] = client_info[0]
            client['cid'] = client_info[1]
            client['kid'] = client_info[2]
        elif line.startswith(">CLIENT:ENV,"):
            client_env = line.split(',')[1].split('=')
            client['env'][client_env[0]] = client_env[1] if len(client_env) == 2 else ''
        else:
            raise errors.ParseError("Can't parse line: %s" % (line, ))

    return client


def is_authenticated(result: dict) -> bool:
    return 'access_token' in result


def format_error(result: dict) -> str:
    return result.get("error") + ': ' + result.get("error_description")
