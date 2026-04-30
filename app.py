import hashlib
import base64
oauth_states = {}

import os
import re
import csv
import io
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
pending_exchanges = {}

def compute_code_challenge(verifier):
    sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode('utf-8').replace('=', '')
app = Flask(__name__)

ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS)

DATABASE_URL  = os.environ.get("DATABASE_URL", "").replace("postgres://", "postgresql://")
BACKEND_URL   = os.environ.get("BACKEND_URL", "http://localhost:5000")
FRONTEND_URL  = os.environ.get("FRONTEND_URL", "http://localhost:3000")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


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


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT pg_advisory_lock(987654321);")
    try:
        c.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name                VARCHAR UNIQUE NOT NULL,
                gender              VARCHAR,
                gender_probability  FLOAT,
                age                 INT,
                age_group           VARCHAR,
                country_id          VARCHAR(2),
                country_name        VARCHAR,
                country_probability FLOAT,
                created_at          TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_filters
            ON profiles(gender, age_group, country_id)
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                github_id     VARCHAR UNIQUE NOT NULL,
                username      VARCHAR,
                email         VARCHAR,
                avatar_url    VARCHAR,
                role          VARCHAR DEFAULT 'analyst'
                    CHECK (role IN ('admin', 'analyst')),
                is_active     BOOLEAN DEFAULT TRUE,
                last_login_at TIMESTAMPTZ,
                created_at    TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
                token_hash  VARCHAR UNIQUE NOT NULL,
                expires_at  TIMESTAMPTZ NOT NULL,
                is_revoked  BOOLEAN DEFAULT FALSE,
                created_at  TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            c.execute("SELECT pg_advisory_unlock(987654321);")
            conn.commit()
        finally:
            conn.close()



def _issue_tokens(user_id: str, role: str, conn=None):
    """Create access + refresh tokens; persist refresh token in DB."""
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


def _set_web_cookies(response, access: str, refresh: str, csrf: str):
    """Set HTTP-only auth cookies for web clients."""
    secure = os.environ.get("FLASK_ENV", "development") == "production"
    kw = dict(httponly=True, samesite="Lax", secure=secure)
    response.set_cookie("access_token",  access,  max_age=3 * 60,    **kw)
    response.set_cookie("refresh_token", refresh, max_age=5 * 60,    **kw)
    
    response.set_cookie("csrf_token", csrf, max_age=5 * 60, samesite="Lax", secure=secure)
    return response



@app.route("/auth/github")
@limiter.limit("10 per minute")
def auth_github():
    """Initiate GitHub OAuth.

    CLI flow params: code_challenge, state (cli_state), redirect_uri (local port)
    Web flow: no code_challenge; redirect_uri not required
    """
    _cleanup()

    backend_state    = secrets.token_urlsafe(16)
    backend_callback = f"{BACKEND_URL}/auth/github/callback"

    code_challenge = request.args.get("code_challenge")
    cli_state      = request.args.get("state")
    cli_redirect   = request.args.get("redirect_uri")

    if code_challenge:
        
        oauth_states[backend_state] = {
            "type":           "cli",
            "code_challenge": code_challenge,
            "cli_state":      cli_state,
            "cli_redirect":   cli_redirect,
            "expires_at":     time.time() + 300,
        }
    else:
        
        oauth_states[backend_state] = {
            "type":       "web",
            "expires_at": time.time() + 300,
        }

    return redirect(build_github_auth_url(backend_state, backend_callback))


@app.route("/auth/github/callback")
def github_callback():
    state = request.args.get('state')
    github_code = request.args.get('code')
    
    user_id, role = process_github_login(github_code)

    if state and state in pending_exchanges:
        pending_exchanges[state].update({
            "user_id": user_id,
            "role": role
        })
        return "<h1>Authenticated! Return to your terminal.</h1>"

    access, refresh = _issue_tokens(user_id, role)
    return redirect(f"https://insighta-web-production-ad10.up.railway.app//index.html?token={access}")
@app.route("/auth/token", methods=["POST"])
@limiter.limit("10 per minute")
def auth_token():
    data = request.get_json() or {}
    code = data.get("code")
    code_verifier = data.get("code_verifier")

    if not code or not code_verifier:
        return jsonify({"status": "error", "message": "Missing code or code_verifier"}), 400

    exchange = pending_exchanges.pop(code, None)
    if not exchange:
        return jsonify({"status": "error", "message": "Invalid or expired code"}), 400

    expected_challenge = exchange["code_challenge"]
    actual_challenge = compute_code_challenge(code_verifier)
    
    if actual_challenge != expected_challenge:
        return jsonify({"status": "error", "message": "PKCE verification failed"}), 400

    user_id = exchange["user_id"]
    role = exchange["role"]

    access, refresh = _issue_tokens(user_id, role)

    from database import get_conn
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    row = c.fetchone()
    username = row[0] if row else "Unknown"
    conn.close()

    return jsonify({
        "status": "success",
        "access_token": access,
        "refresh_token": refresh,
        "username": username,
        "role": role,
    }), 200


@app.route("/auth/refresh", methods=["POST"])
@limiter.limit("10 per minute")
def auth_refresh():
    """Rotate refresh token; issue new access + refresh pair."""
    data          = request.get_json() or {}
    
    refresh_token = data.get("refresh_token") or request.cookies.get("refresh_token")

    if not refresh_token:
        return jsonify({"status": "error", "message": "Missing refresh token"}), 400

    token_hash = hash_token(refresh_token)
    now        = datetime.now(timezone.utc)

    conn = get_conn()
    c    = conn.cursor()
    c.execute(
        "SELECT id, user_id, expires_at, is_revoked FROM refresh_tokens WHERE token_hash = %s",
        (token_hash,),
    )
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Invalid refresh token"}), 401

    rt_id, user_id, expires_at, is_revoked = row

    if is_revoked or (expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at) < now:
        conn.close()
        return jsonify({"status": "error", "message": "Refresh token expired or revoked"}), 401


    c.execute("UPDATE refresh_tokens SET is_revoked = TRUE WHERE id = %s", (str(rt_id),))

    c.execute("SELECT role, is_active FROM users WHERE id = %s", (str(user_id),))
    user_row = c.fetchone()
    if not user_row or not user_row[1]:
        conn.close()
        return jsonify({"status": "error", "message": "Account is inactive"}), 403

    role = user_row[0]

    new_access, new_refresh = _issue_tokens(str(user_id), role, conn)
    conn.close()

    payload = {
        "status":        "success",
        "access_token":  new_access,
        "refresh_token": new_refresh,
    }

    if request.cookies.get("refresh_token"):
        csrf = secrets.token_urlsafe(16)
        resp = make_response(jsonify(payload))
        _set_web_cookies(resp, new_access, new_refresh, csrf)
        return resp

    return jsonify(payload), 200


@app.route("/auth/logout", methods=["POST"])
@limiter.limit("10 per minute")
def auth_logout():
    """Invalidate refresh token."""
    data          = request.get_json() or {}
    refresh_token = data.get("refresh_token") or request.cookies.get("refresh_token")

    if refresh_token:
        token_hash = hash_token(refresh_token)
        try:
            conn = get_conn()
            c    = conn.cursor()
            c.execute(
                "UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_hash = %s",
                (token_hash,),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    resp = make_response(jsonify({"status": "success", "message": "Logged out"}))
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    resp.delete_cookie("csrf_token")
    return resp, 200


@app.route("/auth/me")
@require_auth
def auth_me():
    """Return current user info."""
    conn = get_conn()
    c    = conn.cursor()
    c.execute(
        "SELECT id,username,email,avatar_url,role,is_active,last_login_at,created_at FROM users WHERE id=%s",
        (g.user["id"],),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({
        "status": "success",
        "data": {
            "id":            str(row[0]),
            "username":      row[1],
            "email":         row[2],
            "avatar_url":    row[3],
            "role":          row[4],
            "is_active":     row[5],
            "last_login_at": row[6].strftime("%Y-%m-%dT%H:%M:%SZ") if row[6] else None,
            "created_at":    row[7].strftime("%Y-%m-%dT%H:%M:%SZ") if row[7] else None,
        },
    }), 200


@app.route("/health")
def health():
    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute("SELECT COUNT(*) FROM profiles")
        count = c.fetchone()[0]
        conn.close()
        return jsonify({"status": "ok", "db": "connected", "profiles": count})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500


def _build_pagination_links(page, limit, total, base_path, extra_params):
    total_pages = (total + limit - 1) // limit if limit else 1
    qs          = "".join(f"&{k}={v}" for k, v in extra_params.items() if v is not None)

    def link(p):
        return f"{base_path}?page={p}&limit={limit}{qs}" if p else None

    return {
        "self": link(page),
        "next": link(page + 1) if page < total_pages else None,
        "prev": link(page - 1) if page > 1 else None,
    }, total_pages


def run_query(filters, page, limit, extra_params=None):
    try:
        where, params = [], []

        for key, col in [("gender", "gender"), ("age_group", "age_group"), ("country_id", "country_id")]:
            if key in filters:
                where.append(f"{col} = %s")
                params.append(filters[key])

        if "min_age" in filters:
            where.append("age >= %s"); params.append(filters["min_age"])
        if "max_age" in filters:
            where.append("age <= %s"); params.append(filters["max_age"])
        if "min_gender_probability" in filters:
            where.append("gender_probability >= %s"); params.append(filters["min_gender_probability"])
        if "min_country_probability" in filters:
            where.append("country_probability >= %s"); params.append(filters["min_country_probability"])

        where_sql = "WHERE " + " AND ".join(where) if where else ""
        sort_col  = filters.get("sort_by", "created_at")
        order     = filters.get("order", "asc").upper()
        offset    = (page - 1) * limit

        conn = get_conn()
        c    = conn.cursor()

        c.execute(f"SELECT COUNT(*) FROM profiles {where_sql}", params)
        total = c.fetchone()[0]

        c.execute(
            f"""SELECT id,name,gender,gender_probability,age,age_group,
                       country_id,country_name,country_probability,created_at
                FROM profiles {where_sql}
                ORDER BY {sort_col} {order}
                LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
        rows = c.fetchall()
        conn.close()

        data = [_row_to_dict(r) for r in rows]

        links, total_pages = _build_pagination_links(
            page, limit, total,
            request.path,
            extra_params or {},
        )

        return jsonify({
            "status":      "success",
            "page":        page,
            "limit":       limit,
            "total":       total,
            "total_pages": total_pages,
            "links":       links,
            "data":        data,
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


def _row_to_dict(r):
    return {
        "id":                  str(r[0]),
        "name":                r[1],
        "gender":              r[2],
        "gender_probability":  r[3],
        "age":                 r[4],
        "age_group":           r[5],
        "country_id":          r[6],
        "country_name":        r[7],
        "country_probability": r[8],
        "created_at":          r[9].strftime("%Y-%m-%dT%H:%M:%SZ"),
    }



def parse_nl(q):
    s = q.lower().strip()
    f = {}

    has_male   = "male" in s
    has_female = "female" in s
    if has_male and not has_female:
        f["gender"] = "male"
    elif has_female and not has_male:
        f["gender"] = "female"

    if "child" in s:       f["age_group"] = "child"
    elif "teen" in s:      f["age_group"] = "teenager"
    elif "adult" in s:     f["age_group"] = "adult"
    elif "senior" in s:    f["age_group"] = "senior"

    if "young" in s:
        f["min_age"] = 16
        f["max_age"] = 24

    m = re.search(r"(above|over|older than)\s+(\d+)", s)
    if m: f["min_age"] = int(m.group(2))

    m = re.search(r"(below|under|younger than)\s+(\d+)", s)
    if m: f["max_age"] = int(m.group(2))

    m = re.search(r"(from|in)\s+([a-z\s]+)", s)
    if m:
        name = m.group(2).strip()
        cid  = COUNTRY_NAME_TO_ID.get(name)
        if cid:
            f["country_id"] = cid

    return f if f else None


@app.route("/api/profiles", methods=["GET"])
@require_auth
@require_version
def get_profiles():
    try:
        page  = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 10))
        if page < 1 or limit < 1 or limit > 50:
            raise ValueError
    except Exception:
        return jsonify({"status": "error", "message": "Invalid query parameters"}), 422

    filters = {}
    extra   = {"page": page, "limit": limit}

    if g_val := request.args.get("gender"):
        if g_val not in VALID_GENDERS:
            return jsonify({"status": "error", "message": "Invalid query parameters"}), 422
        filters["gender"] = g_val
        extra["gender"]   = g_val

    if ag := request.args.get("age_group"):
        if ag not in VALID_AGE_GROUPS:
            return jsonify({"status": "error", "message": "Invalid query parameters"}), 422
        filters["age_group"] = ag
        extra["age_group"]   = ag

    if cid := request.args.get("country_id"):
        if not re.match(r"^[A-Za-z]{2}$", cid):
            return jsonify({"status": "error", "message": "Invalid query parameters"}), 422
        filters["country_id"] = cid.upper()
        extra["country_id"]   = cid.upper()

    try:
        for k in ("min_age", "max_age"):
            if v := request.args.get(k):
                filters[k] = int(v)
                extra[k]   = int(v)
        for k in ("min_gender_probability", "min_country_probability"):
            if v := request.args.get(k):
                filters[k] = float(v)
                extra[k]   = float(v)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid query parameters"}), 422

    if s := request.args.get("sort_by"):
        if s not in VALID_SORT_COLS:
            return jsonify({"status": "error", "message": "Invalid query parameters"}), 422
        filters["sort_by"] = s
        extra["sort_by"]   = s

    if o := request.args.get("order", "asc"):
        if o not in ("asc", "desc"):
            return jsonify({"status": "error", "message": "Invalid query parameters"}), 422
        filters["order"] = o
        extra["order"]   = o

    return run_query(filters, page, limit, extra)


@app.route("/api/profiles/search", methods=["GET"])
@require_auth
@require_version
def search_profiles():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"status": "error", "message": "Invalid query parameters"}), 400

    filters = parse_nl(q)
    if not filters:
        return jsonify({"status": "error", "message": "Unable to interpret query"}), 400

    page  = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 10))

    return run_query(filters, page, limit, {"q": q, "page": page, "limit": limit})


@app.route("/api/profiles/export", methods=["GET"])
@require_auth
@require_version
def export_profiles():
    """Export profiles as CSV, with same filters as GET /api/profiles."""
    fmt = request.args.get("format", "csv")
    if fmt != "csv":
        return jsonify({"status": "error", "message": "Only format=csv is supported"}), 400

    filters = {}

    if g_val := request.args.get("gender"):
        if g_val in VALID_GENDERS:
            filters["gender"] = g_val

    if ag := request.args.get("age_group"):
        if ag in VALID_AGE_GROUPS:
            filters["age_group"] = ag

    if cid := request.args.get("country_id"):
        if re.match(r"^[A-Za-z]{2}$", cid):
            filters["country_id"] = cid.upper()

    try:
        if v := request.args.get("min_age"):          filters["min_age"]          = int(v)
        if v := request.args.get("max_age"):          filters["max_age"]          = int(v)
        if v := request.args.get("min_gender_probability"): filters["min_gender_probability"] = float(v)
        if v := request.args.get("min_country_probability"): filters["min_country_probability"] = float(v)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid query parameters"}), 422

    if s := request.args.get("sort_by"):
        if s in VALID_SORT_COLS:
            filters["sort_by"] = s
    if o := request.args.get("order", "asc"):
        if o in ("asc", "desc"):
            filters["order"] = o

    where, params = [], []
    for key, col in [("gender", "gender"), ("age_group", "age_group"), ("country_id", "country_id")]:
        if key in filters:
            where.append(f"{col} = %s"); params.append(filters[key])
    if "min_age" in filters:
        where.append("age >= %s"); params.append(filters["min_age"])
    if "max_age" in filters:
        where.append("age <= %s"); params.append(filters["max_age"])
    if "min_gender_probability" in filters:
        where.append("gender_probability >= %s"); params.append(filters["min_gender_probability"])
    if "min_country_probability" in filters:
        where.append("country_probability >= %s"); params.append(filters["min_country_probability"])

    where_sql = "WHERE " + " AND ".join(where) if where else ""
    sort_col  = filters.get("sort_by", "created_at")
    order     = filters.get("order", "asc").upper()

    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute(
            f"""SELECT id,name,gender,gender_probability,age,age_group,
                       country_id,country_name,country_probability,created_at
                FROM profiles {where_sql}
                ORDER BY {sort_col} {order}""",
            params,
        )
        rows = c.fetchall()
        conn.close()
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

    output    = io.StringIO()
    writer    = csv.writer(output)
    writer.writerow(["id", "name", "gender", "gender_probability", "age", "age_group",
                     "country_id", "country_name", "country_probability", "created_at"])
    for r in rows:
        writer.writerow([
            str(r[0]), r[1], r[2], r[3], r[4], r[5],
            r[6], r[7], r[8],
            r[9].strftime("%Y-%m-%dT%H:%M:%SZ"),
        ])

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    resp      = make_response(output.getvalue())
    resp.headers["Content-Type"]        = "text/csv"
    resp.headers["Content-Disposition"] = f'attachment; filename="profiles_{timestamp}.csv"'
    return resp, 200


@app.route("/api/profiles", methods=["POST"])
@require_auth
@require_admin
@require_version
@require_csrf
def create_profile():
    data = request.get_json()
    if not data or not data.get("name"):
        return jsonify({"status": "error", "message": "Missing or empty name"}), 400

    name = data["name"].strip().lower()

    conn = get_conn()
    c    = conn.cursor()

    c.execute(
        """SELECT id,name,gender,gender_probability,age,age_group,
                  country_id,country_name,country_probability,created_at
           FROM profiles WHERE name=%s""",
        (name,),
    )
    row = c.fetchone()
    if row:
        conn.close()
        return jsonify({"status": "success", "data": _row_to_dict(row)}), 200

    try:
        g_r = req.get(f"https://api.genderize.io/?name={name}", timeout=10)
        a_r = req.get(f"https://api.agify.io/?name={name}", timeout=10)
        n_r = req.get(f"https://api.nationalize.io/?name={name}", timeout=10)

        if g_r.status_code != 200 or a_r.status_code != 200 or n_r.status_code != 200:
            conn.close()
            return jsonify({"status": "error", "message": "Upstream server failure"}), 502

        g_d, a_d, n_d = g_r.json(), a_r.json(), n_r.json()
    except Exception:
        conn.close()
        return jsonify({"status": "error", "message": "Upstream server failure"}), 502

    if not g_d.get("gender") or a_d.get("age") is None or not n_d.get("country"):
        conn.close()
        return jsonify({"status": "error", "message": "Upstream server failure"}), 502

    age     = a_d["age"]
    country = max(n_d["country"], key=lambda x: x["probability"])
    cid     = country["country_id"]
    pid     = str(uuid6.uuid7())

    c.execute(
        """INSERT INTO profiles
               (id,name,gender,gender_probability,age,age_group,country_id,country_name,country_probability,created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
           RETURNING id,name,gender,gender_probability,age,age_group,country_id,country_name,country_probability,created_at""",
        (
            pid, name, g_d["gender"], g_d["probability"],
            age, age_to_group(age),
            cid, COUNTRY_ID_TO_NAME.get(cid, cid), country["probability"],
        ),
    )
    saved = c.fetchone()
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "data": _row_to_dict(saved)}), 201


@app.route("/api/profiles/<profile_id>", methods=["GET"])
@require_auth
@require_version
def get_profile(profile_id):
    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute(
            """SELECT id,name,gender,gender_probability,age,age_group,
                      country_id,country_name,country_probability,created_at
               FROM profiles WHERE id = %s""",
            (profile_id,),
        )
        row = c.fetchone()
        conn.close()
        if not row:
            return jsonify({"status": "error", "message": "Profile not found"}), 404
        return jsonify({"status": "success", "data": _row_to_dict(row)}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.errorhandler(404)
def _not_found(_):
    return jsonify({"status": "error", "message": "Not found"}), 404


@app.errorhandler(500)
def _server_error(e):
    traceback.print_exc()
    return jsonify({"status": "error", "message": "Internal server error"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
