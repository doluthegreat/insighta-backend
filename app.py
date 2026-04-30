import os
import hashlib
import base64
import secrets
import time
import traceback
import logging
from datetime import datetime, timezone, timedelta

import jwt as pyjwt
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
    compute_code_challenge,
    create_access_token,
    decode_access_token,
    exchange_github_code,
    get_github_primary_email,
    get_github_user,
    hash_token,
    new_refresh_token,
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

DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgres://", "postgresql://")
BACKEND_URL = os.environ.get("BACKEND_URL", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "")

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)




def create_oauth_state(data: dict) -> str:
    payload = {
        **data,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }
    return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_oauth_state(token: str) -> dict:
    return pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])




def get_conn():
    return psycopg2.connect(DATABASE_URL)

@app.route("/auth/github")
def auth_github():
    _cleanup()

    backend_state = create_oauth_state({
        "type": "cli" if request.args.get("code_challenge") else "web",
        "code_challenge": request.args.get("code_challenge"),
        "cli_state": request.args.get("state"),
        "cli_redirect": request.args.get("redirect_uri"),
        "ts": time.time()
    })

    callback_url = f"{BACKEND_URL}/auth/github/callback"

    return redirect(build_github_auth_url(backend_state, callback_url))


@app.route("/auth/github/callback")
def github_callback():
    try:
        state = request.args.get("state")
        code = request.args.get("code")

        if not state or not code:
            return jsonify({"status": "error", "message": "Missing state or code"}), 400

        flow = decode_oauth_state(state)

        redirect_uri = f"{BACKEND_URL}/auth/github/callback"

        token_response = exchange_github_code(code, redirect_uri)
        access_token = token_response.get("access_token")

        user = get_github_user(access_token)
        email = get_github_primary_email(access_token)

        conn = get_conn()
        c = conn.cursor()

        c.execute("SELECT id, role FROM users WHERE github_id = %s", (str(user["id"]),))
        row = c.fetchone()

        if row:
            user_id, role = row
        else:
            user_id = str(uuid6.uuid7())
            role = "analyst"

            c.execute(
                """
                INSERT INTO users (id, github_id, username, email, avatar_url, role)
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (
                    user_id,
                    str(user["id"]),
                    user["login"],
                    email,
                    user.get("avatar_url"),
                    role,
                ),
            )
            conn.commit()

        conn.close()

        from auth import create_access_token, new_refresh_token, hash_token

        access = create_access_token(user_id, role)
        refresh = new_refresh_token()

        return redirect(f"{FRONTEND_URL}/index.html?token={access}")

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route("/auth/token", methods=["POST"])
def auth_token():
    data = request.get_json() or {}

    code = data.get("code")
    verifier = data.get("code_verifier")

    if not code or not verifier:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    from auth import pending_exchanges

    exchange = pending_exchanges.pop(code, None)

    if not exchange:
        return jsonify({"status": "error", "message": "Invalid code"}), 400

    expected = exchange["code_challenge"]
    actual = hashlib.sha256(verifier.encode()).digest()
    actual = base64.urlsafe_b64encode(actual).decode().replace("=", "")

    if actual != expected:
        return jsonify({"status": "error", "message": "PKCE failed"}), 400

    user_id = exchange["user_id"]
    role = exchange["role"]

    access = create_access_token(user_id, role)
    refresh = new_refresh_token()

    return jsonify({
        "status": "success",
        "access_token": access,
        "refresh_token": refresh,
    })



@app.route("/")
def home():
    return jsonify({"message": "Insighta API running", "status": "ok"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})



@app.errorhandler(404)
def nf(_):
    return jsonify({"status": "error", "message": "Not found"}), 404


@app.errorhandler(500)
def se(e):
    traceback.print_exc()
    return jsonify({"status": "error", "message": "Internal server error"}), 500




if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)