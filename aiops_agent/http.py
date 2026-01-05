import requests
from requests.auth import HTTPBasicAuth

def build_headers(bearer_token: str | None) -> dict:
    headers = {"Accept": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers

def build_auth(basic_user: str | None, basic_pass: str | None):
    if basic_user and basic_pass:
        return HTTPBasicAuth(basic_user, basic_pass)
    return None

def get_json(url: str, params: dict, headers: dict, auth=None, timeout: int = 15) -> dict:
    resp = requests.get(url, params=params, headers=headers, auth=auth, timeout=timeout)
    resp.raise_for_status()
    return resp.json()