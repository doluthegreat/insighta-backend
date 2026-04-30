import os
import hashlib
import base64
import secrets
import time
from datetime import datetime, timezone, timedelta

import jwt
import requests as req

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")

ACCESS_TOKEN_EXPIRY = 3 * 60
REFRESH_TOKEN_EXPIRY = 5 * 60

oauth_states = {}
pending_exchanges = {}


def _cleanup():
    now = time.time()
    for store in (oauth_states, pending_exchanges):
        expired = [k for k, v in store.items() if v.get("expires_at", 0) < now]
        for k in expired:
            del store[k]


def compute_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def build_github_auth_url(backend_state: str, callback_url: str) -> str:
    params = (
        f"client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={callback_url}"
        f"&scope=user:email+read:user"
        f"&state={backend_state}"
    )
    return f"https://github.com/login/oauth/authorize?{params}"


def exchange_github_code(code: str, redirect_uri: str, code_verifier: str | None = None) -> str:
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": redirect_uri,
    }

    if code_verifier:
        data["code_verifier"] = code_verifier

    resp = req.post(
        "https://github.com/login/oauth/access_token",
        data=data,
        headers={"Accept": "application/json"},
        timeout=10,
    )

    try:
        result = resp.json()
    except Exception:
        raise Exception(f"GitHub returned invalid response: {resp.text}")

    if resp.status_code != 200:
        raise Exception(f"GitHub OAuth error: {result}")

    if "error" in result:
        raise Exception(f"GitHub OAuth failed: {result}")

    return result["access_token"]


def get_github_user(token: str) -> dict:
    resp = req.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        },
        timeout=10,
    )

    try:
        resp.raise_for_status()
    except Exception:
        raise Exception(f"GitHub user fetch failed: {resp.text}")

    return resp.json()


def get_github_primary_email(token: str) -> str | None:
    resp = req.get(
        "https://api.github.com/user/emails",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        },
        timeout=10,
    )

    if resp.status_code != 200:
        return None

    for entry in resp.json():
        if entry.get("primary") and entry.get("verified"):
            return entry.get("email")

    return None


def create_access_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRY),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


def new_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()