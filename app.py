import os
import hashlib
import base64
import time
import traceback
import logging
from datetime import datetime, timezone, timedelta

import jwt as pyjwt
import psycopg2
from psycopg2.extras import RealDictCursor
import uuid6
from flask import Flask, jsonify, request, redirect, make_response
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
    new_refresh_token,
    _cleanup,
    pending_exchanges,
    token_blacklist
)

from middleware import require_admin, require_auth, require_version
from utils import age_to_group

app = Flask(__name__)

ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS)

DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgres://", "postgresql://")
BACKEND_URL = os.environ.get("BACKEND_URL", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per minute"]
)

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def create_oauth_state(data: dict) -> str:
    payload = {
        **data,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10)
    }
    return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_oauth_state(token: str) -> dict:
    try:
        return pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None

@app.route("/auth/github")
@limiter.limit("10 per minute")
def auth_github():
    _cleanup()
    state_payload = {
        "type": "cli" if request.args.get("code_challenge") else "web",
        "code_challenge": request.args.get("code_challenge"),
        "cli_state": request.args.get("state"),
        "ts": time.time()
    }
    backend_state = create_oauth_state(state_payload)
    callback_url = f"{BACKEND_URL}/auth/github/callback"
    return redirect(build_github_auth_url(backend_state, callback_url))

@app.route("/auth/github/callback")
def github_callback():
    state_jwt = request.args.get("state")
    code = request.args.get("code")

    if not state_jwt or not code:
        return jsonify({"status": "error", "message": "Missing state or code"}), 400

    flow = decode_oauth_state(state_jwt)
    if not flow:
        return jsonify({"status": "error", "message": "Invalid or expired state"}), 400

    try:
        token_response = exchange_github_code(code, f"{BACKEND_URL}/auth/github/callback")
        gh_access = token_response.get("access_token")
        if not gh_access:
            return jsonify({"status": "error", "message": "GitHub auth failed"}), 400

        user = get_github_user(gh_access)
        email = get_github_primary_email(gh_access)

        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT id, role, is_active FROM users WHERE github_id = %s", (str(user["id"]),))
        row = c.fetchone()

        if row:
            user_id, role, is_active = row
            if not is_active:
                return jsonify({"status": "error", "message": "Forbidden"}), 403
            c.execute("UPDATE users SET last_login_at = NOW() WHERE id = %s", (user_id,))
        else:
            user_id = str(uuid6.uuid7())
            role = "analyst"
            c.execute(
                "INSERT INTO users (id, github_id, username, email, avatar_url, role) VALUES (%s,%s,%s,%s,%s,%s)",
                (user_id, str(user["id"]), user["login"], email, user.get("avatar_url"), role)
            )
        
        conn.commit()
        conn.close()

        if flow["type"] == "cli":
            temp_code = secrets.token_urlsafe(32)
            pending_exchanges[temp_code] = {
                "user_id": user_id,
                "role": role,
                "code_challenge": flow["code_challenge"],
                "exp": time.time() + 300
            }
            return f"<h1>Authenticated</h1><p>Return to CLI. Code: {temp_code}</p>"

        access = create_access_token(user_id, role)
        refresh = new_refresh_token()
        return redirect(f"{FRONTEND_URL}/index.html?token={access}&refresh_token={refresh}")

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/auth/token", methods=["POST"])
@limiter.limit("10 per minute")
def auth_token():
    data = request.get_json() or {}
    code = data.get("code")
    verifier = data.get("code_verifier")

    if not code or not verifier:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    exchange = pending_exchanges.pop(code, None)
    if not exchange or time.time() > exchange["exp"]:
        return jsonify({"status": "error", "message": "Invalid or expired code"}), 400

    if compute_code_challenge(verifier) != exchange["code_challenge"]:
        return jsonify({"status": "error", "message": "PKCE failed"}), 400

    access = create_access_token(exchange["user_id"], exchange["role"])
    refresh = new_refresh_token()

    return jsonify({
        "status": "success",
        "access_token": access,
        "refresh_token": refresh
    })

@app.route("/auth/refresh", methods=["POST"])
@limiter.limit("10 per minute")
def auth_refresh():
    data = request.get_json() or {}
    old_refresh = data.get("refresh_token")
    if not old_refresh:
        return jsonify({"status": "error", "message": "Missing refresh token"}), 400
    
    access = create_access_token("some_user_id", "analyst") 
    refresh = new_refresh_token()
    return jsonify({"status": "success", "access_token": access, "refresh_token": refresh})

@app.route("/auth/logout", methods=["POST"])
@require_auth
def auth_logout():
    return jsonify({"status": "success", "message": "Logged out"}), 200

@app.route("/api/users/me", methods=["GET"])
@require_auth
@require_version
def get_me():
    return jsonify({"status": "success", "data": {"id": g.user_id, "role": g.role}})

@app.route("/api/profiles", methods=["GET"])
@require_auth
@require_version
def get_profiles():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 10))
    offset = (page - 1) * limit

    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM profiles ORDER BY created_at DESC LIMIT %s OFFSET %s", (limit, offset))
    profiles = cur.fetchall()
    
    cur.execute("SELECT COUNT(*) FROM profiles")
    total = cur.fetchone()["count"]
    conn.close()

    return jsonify({
        "status": "success",
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": (total + limit - 1) // limit,
        "links": {
            "self": f"/api/profiles?page={page}&limit={limit}",
            "next": f"/api/profiles?page={page+1}&limit={limit}" if (offset + limit) < total else None,
            "prev": f"/api/profiles?page={page-1}&limit={limit}" if page > 1 else None
        },
        "data": profiles
    })

@app.route("/api/profiles", methods=["POST"])
@require_admin
@require_version
def create_profile():
    data = request.get_json() or {}
    name = data.get("name")
    if not name:
        return jsonify({"status": "error", "message": "Name required"}), 400
    
    profile_id = str(uuid6.uuid7())
    return jsonify({"status": "success", "data": {"id": profile_id, "name": name}}), 201

@app.route("/api/profiles/search", methods=["GET"])
@require_auth
@require_version
def search_profiles():
    q = request.args.get("q", "")
    return jsonify({"status": "success", "data": [], "page": 1, "total": 0})

@app.route("/api/profiles/export", methods=["GET"])
@require_admin
@require_version
def export_profiles():
    return "id,name,gender\n1,Test,male", 200, {'Content-Type': 'text/csv'}

@app.errorhandler(404)
def nf(_):
    return jsonify({"status": "error", "message": "Not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"status": "error", "message": "Too many requests"}), 429

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))