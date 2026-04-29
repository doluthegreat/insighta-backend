import os
import hashlib
import base64
import secrets
import time
from datetime import datetime, timezone, timedelta

import jwt
import requests as req

SECRET_KEY            = os.environ.get("SECRET_KEY", "dev-secret-change-me")
GITHUB_CLIENT_ID      = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET  = os.environ.get("GITHUB_CLIENT_SECRET", "")

ACCESS_TOKEN_EXPIRY   = 3 * 60   # 3 minutes
REFRESH_TOKEN_EXPIRY  = 5 * 60   # 5 minutes

# ─── In-memory short-lived stores ────────────────────────────────────────────
# {backend_state: {type, code_challenge, cli_redirect, cli_state, expires_at}}
oauth_states: dict = {}

# {gh_code: {code_challenge, expires_at}}
pending_exchanges: dict = {}


def _cleanup():
    """Remove expired entries."""
    now = time.time()
    for store in (oauth_states, pending_exchanges):
        expired = [k for k, v in store.items() if v.get("expires_at", 0) < now]
        for k in expired:
            del store[k]


# ─── PKCE helpers ─────────────────────────────────────────────────────────────
def compute_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# ─── GitHub helpers ───────────────────────────────────────────────────────────
def build_github_auth_url(backend_state: str, callback_url: str) -> str:
    params = (
        f"client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={callback_url}"
        f"&scope=user:email+read:user"
        f"&state={backend_state}"
    )
    return f"https://github.com/login/oauth/authorize?{params}"


def exchange_github_code(code: str, redirect_uri: str) -> dict:
    """Exchange GitHub code for an access token using client_secret."""
    resp = req.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id":     GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code":          code,
            "redirect_uri":  redirect_uri,
        },
        headers={"Accept": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def get_github_user(gh_access_token: str) -> dict:
    resp = req.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {gh_access_token}",
            "Accept": "application/vnd.github.v3+json",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def get_github_primary_email(gh_access_token: str) -> str | None:
    resp = req.get(
        "https://api.github.com/user/emails",
        headers={
            "Authorization": f"Bearer {gh_access_token}",
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


# ─── JWT ──────────────────────────────────────────────────────────────────────
def create_access_token(user_id: str, role: str) -> str:
    payload = {
        "sub":  user_id,
        "role": role,
        "type": "access",
        "iat":  datetime.now(timezone.utc),
        "exp":  datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRY),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


# ─── Refresh tokens ───────────────────────────────────────────────────────────
def new_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
