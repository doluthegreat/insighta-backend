from functools import wraps
from flask import request, jsonify, g
import jwt as pyjwt

from auth import decode_access_token


def _extract_token() -> str | None:
    """Pull Bearer token from Authorization header or access_token cookie."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("access_token")


def require_auth(f):
    """Decorator: validates access token, sets g.user."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        try:
            payload = decode_access_token(token)
        except pyjwt.ExpiredSignatureError:
            return jsonify({"status": "error", "message": "Token expired"}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({"status": "error", "message": "Invalid token"}), 401

        if payload.get("type") != "access":
            return jsonify({"status": "error", "message": "Invalid token type"}), 401

        g.user = {"id": payload["sub"], "role": payload["role"]}

        from app import get_conn
        try:
            conn = get_conn()
            c = conn.cursor()
            c.execute("SELECT is_active FROM users WHERE id = %s", (g.user["id"],))
            row = c.fetchone()
            conn.close()
        except Exception:
            return jsonify({"status": "error", "message": "Internal server error"}), 500

        if not row or not row[0]:
            return jsonify({"status": "error", "message": "Account is inactive"}), 403

        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    """Decorator: must be called after @require_auth."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not hasattr(g, "user") or g.user.get("role") != "admin":
            return jsonify({"status": "error", "message": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper


def require_version(f):
    """Decorator: enforces X-API-Version: 1 header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-API-Version") != "1":
            return jsonify({"status": "error", "message": "API version header required"}), 400
        return f(*args, **kwargs)
    return wrapper


def require_csrf(f):
    """Decorator: validates CSRF token for web clients using cookies."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        
        if request.cookies.get("access_token"):
            client_csrf  = request.headers.get("X-CSRF-Token", "")
            cookie_csrf  = request.cookies.get("csrf_token", "")
            if not client_csrf or client_csrf != cookie_csrf:
                return jsonify({"status": "error", "message": "CSRF token invalid"}), 403
        return f(*args, **kwargs)
    return wrapper
