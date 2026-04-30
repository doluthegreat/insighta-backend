import hashlib
import base64
import os
import re
import csv
import io
import secrets
import time
import traceback
import logging
from datetime import datetime, timezone, timedelta

import psycopg2
import requests as req
import uuid6
from flask import Flask, jsonify, request, redirect, make_response, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from auth import (
    REFRESH_TOKEN_EXPIRY,
    build_github_auth_url,
    create_access_token,
    exchange_github_code,
    get_github_primary_email,
    get_github_user,
    hash_token,
    new_refresh_token,
    oauth_states,
    pending_exchanges,
    _cleanup,
)

from middleware import require_admin, require_auth, require_csrf, require_version
from utils import (
    COUNTRY_ID_TO_NAME,
    COUNTRY_NAME_TO_ID,
    VALID_AGE_GROUPS,
    VALID_GENDERS,
    VALID_SORT_COLS,
    age_to_group,
)

app = Flask(__name__)

ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS)

DATABASE_URL  = os.environ.get("DATABASE_URL", "").replace("postgres://", "postgresql://")
BACKEND_URL   = os.environ.get("BACKEND_URL", "http://localhost:5000")
FRONTEND_URL  = os.environ.get("FRONTEND_URL", "http://localhost:3000")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

@app.route("/")
def root():
    return jsonify({"status": "ok", "message": "Insighta API running"})

@app.before_request
def _start_timer():
    g.start_time = time.time()

@app.after_request
def _log_request(response):
    ms = round((time.time() - g.start_time) * 1000, 2) if hasattr(g, "start_time") else "-"
    logger.info("%s %s %s %sms", request.method, request.path, response.status_code, ms)
    return response

def _rate_limit_key():
    if hasattr(g, "user") and g.user:
        return f"user:{g.user['id']}"
    return get_remote_address()

limiter = Limiter(
    key_func=_rate_limit_key,
    app=app,
    storage_uri="memory://",
    default_limits=["60 per minute"],
)

@app.errorhandler(429)
def _rate_limit_error(e):
    return jsonify({"status": "error", "message": "Too many requests"}), 429

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def compute_code_challenge(verifier):
    sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode('utf-8').replace('=', '')

def process_github_login(code):
    backend_callback = f"{BACKEND_URL}/auth/github/callback"
    access_token = exchange_github_code(code, backend_callback)
    user = get_github_user(access_token)
    email = get_github_primary_email(access_token)

    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT id, role FROM users WHERE github_id = %s", (str(user["id"]),))
    row = c.fetchone()

    if row:
        user_id, role = row
        c.execute("UPDATE users SET last_login_at = NOW() WHERE id = %s", (str(user_id),))
    else:
        user_id = str(uuid6.uuid7())
        role = "analyst"
        c.execute(
            """INSERT INTO users (id, github_id, username, email, avatar_url)
               VALUES (%s,%s,%s,%s,%s)""",
            (user_id, str(user["id"]), user["login"], email, user["avatar_url"]),
        )

    conn.commit()
    conn.close()
    return user_id, role

def _issue_tokens(user_id: str, role: str, conn=None):
    close_conn = False
    if conn is None:
        conn = get_conn()
        close_conn = True

    access  = create_access_token(user_id, role)
    refresh = new_refresh_token()
    r_hash  = hash_token(refresh)
    expires = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXPIRY)

    c = conn.cursor()
    c.execute(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (%s,%s,%s,%s)",
        (str(uuid6.uuid7()), user_id, r_hash, expires),
    )
    conn.commit()
    if close_conn:
        conn.close()

    return access, refresh

@app.route("/auth/github")
def auth_github():
    _cleanup()

    backend_state = secrets.token_urlsafe(16)
    backend_callback = f"{BACKEND_URL}/auth/github/callback"

    code_challenge = request.args.get("code_challenge")
    cli_state = request.args.get("state")
    cli_redirect = request.args.get("redirect_uri")

    if code_challenge:
        oauth_states[backend_state] = {
            "type": "cli",
            "code_challenge": code_challenge,
            "cli_state": cli_state,
            "cli_redirect": cli_redirect,
            "expires_at": time.time() + 300,
        }
    else:
        oauth_states[backend_state] = {
            "type": "web",
            "expires_at": time.time() + 300,
        }

    return redirect(build_github_auth_url(backend_state, backend_callback))

@app.route("/auth/github/callback")
def github_callback():
    state = request.args.get("state")
    github_code = request.args.get("code")

    if not state or state not in oauth_states:
        return jsonify({"status": "error", "message": "Invalid state"}), 400

    flow = oauth_states.pop(state)

    if flow["expires_at"] < time.time():
        return jsonify({"status": "error", "message": "State expired"}), 400

    user_id, role = process_github_login(github_code)

    if flow["type"] == "cli":
        exchange_code = secrets.token_urlsafe(16)

        pending_exchanges[exchange_code] = {
            "user_id": user_id,
            "role": role,
            "code_challenge": flow["code_challenge"],
            "expires_at": time.time() + 300,
        }

        return f"""
        <h1>Authenticated</h1>
        <script>
        window.location = "{flow['cli_redirect']}?code={exchange_code}&state={flow['cli_state']}";
        </script>
        """

    access, refresh = _issue_tokens(user_id, role)
    return redirect(f"{FRONTEND_URL}/index.html?token={access}&refresh_token={refresh}")

@app.route("/auth/token", methods=["POST"])
def auth_token():
    data = request.get_json() or {}
    code = data.get("code")
    code_verifier = data.get("code_verifier")

    exchange = pending_exchanges.pop(code, None)
    if not exchange or exchange["expires_at"] < time.time():
        return jsonify({"status": "error", "message": "Invalid or expired code"}), 400

    if compute_code_challenge(code_verifier) != exchange["code_challenge"]:
        return jsonify({"status": "error", "message": "PKCE verification failed"}), 400

    access, refresh = _issue_tokens(exchange["user_id"], exchange["role"])

    return jsonify({
        "status": "success",
        "access_token": access,
        "refresh_token": refresh,
        "role": exchange["role"]
    }), 200