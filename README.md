# insighta-backend

 The single source of truth for Insighta Labs+. A secure REST API that handles authentication, role-based access control, profile intelligence, and data export — shared by the CLI and web portal.

---

## About

Insighta Labs+ started as an internal name enrichment tool: give it a name, it returns predicted gender, age, and nationality using public inference APIs. This backend is Stage 3 of that system — the upgrade that makes it production-usable.

Before this stage, there was no authentication, no ownership, and no access control. Anyone with the URL could read or write anything. This backend fixes all of that. It adds GitHub OAuth with PKCE, short-lived JWT sessions, role-based permissions, CSV export, rate limiting, and structured request logging. The CLI and web portal both talk exclusively to this backend — there is no separate data store per interface.

---

## System Architecture

```
                        ┌─────────────────────────────────┐
                        │         insighta-backend        │
                        │                                 │
  insighta-cli  ───────▶│  /auth/*   — OAuth + tokens     │
                        │  /api/*    — profiles (v1)       │◀────  GitHub API
  insighta-web  ───────▶│                                 │       (genderize / agify /
                        │  PostgreSQL                     │        nationalize / oauth)
                        │  (profiles + users + tokens)    │
                        └─────────────────────────────────┘
```

**Single source of truth.** Both interfaces hit the same endpoints, read from the same database, and go through the same middleware stack. There is no CLI-only or web-only data path.

**Middleware stack (applied in order on every request):**

```
Request
  └── CORS headers
  └── Request logger (method, path, status, duration, user id)
  └── Rate limiter (per-IP per-endpoint sliding window)
  └── [/api/*] require_api_version — rejects if X-API-Version != "1"
  └── [/api/*] require_auth — verifies JWT, loads user into g
  └── [/api/* write ops] require_role("admin") — checks g.user_role
  └── [/api/* web mutations] csrf_protect — double-submit cookie check
  └── Route handler
```

**File layout:**

```
insighta-backend/
├── app.py            # Flask app factory, blueprint registration, CORS, error handlers
├── auth.py           # All /auth/* routes (OAuth, PKCE, token refresh, logout, whoami)
├── profiles.py       # All /api/profiles/* routes
├── middleware.py     # Rate limiting, JWT auth, RBAC, CSRF, API version, logging
├── db.py             # Connection helper, schema initialisation
├── utils.py          # Shared constants and the natural language query parser
├── requirements.txt
├── Procfile          # gunicorn entry point for Railway
└── .env.example
```

---

## Authentication Flow

### Web browser flow

```
Browser                     Backend                       GitHub
  │                            │                             │
  │── GET /auth/github ────────▶│                            │
  │                            │ generate state              │
  │                            │ generate code_verifier      │
  │                            │ code_challenge =            │
  │                            │   BASE64URL(SHA256(verifier))│
  │                            │ store (state → verifier) in DB
  │◀── 302 → github.com/login ─│                             │
  │     ?client_id=...         │                             │
  │     &state=...             │                             │
  │     &code_challenge=...    │                             │
  │     &code_challenge_method=S256                          │
  │                            │                             │
  │── user approves ───────────────────────────────────────▶│
  │                            │                             │
  │                            │◀── GET /auth/github/callback│
  │                            │     ?code=...&state=...     │
  │                            │                             │
  │                            │ validate state              │
  │                            │ fetch verifier from DB      │
  │                            │ verify SHA256(verifier)     │
  │                            │   matches stored challenge  │
  │                            │ exchange code with GitHub   │
  │                            │ upsert user in DB           │
  │                            │ issue access + refresh token│
  │◀── 302 → frontend/auth/callback (cookies set) ──────────│
```

### CLI flow (PKCE without server secret)

```
CLI                         Backend                       GitHub
  │                            │                             │
  │ generate code_verifier (local, random bytes)             │
  │ code_challenge = BASE64URL(SHA256(verifier))             │
  │ generate state                                           │
  │ start local HTTP server on random port                   │
  │ open browser → github.com/login                         │
  │   ?client_id=...&state=...&code_challenge=...            │
  │                            │                             │
  │── user approves ───────────────────────────────────────▶│
  │                            │                             │
  │◀── GET localhost:{port}/callback?code=...&state=... ─────│
  │                            │                             │
  │ validate state matches local value                       │
  │                            │                             │
  │── POST /auth/cli/exchange ─▶│                             │
  │   { code, code_verifier,   │                             │
  │     code_challenge,        │ verify SHA256(code_verifier)│
  │     redirect_uri }         │   == code_challenge         │
  │                            │ exchange code with GitHub   │
  │                            │ upsert user                 │
  │                            │ issue access + refresh token│
  │◀── { access_token,         │                             │
  │      refresh_token, user } │                             │
  │                            │                             │
  │ write to ~/.insighta/credentials.json                    │
  │ print "Logged in as @username"                           │
```

**Why PKCE?** The CLI runs on the user's machine — you cannot embed a `client_secret` in a distributed binary without it being extractable. PKCE replaces the secret with a cryptographic proof the client generates fresh for every login. The verifier never leaves the client; only its hash (the challenge) travels over the network.

---

## Token Handling

| Token | Type | Lifetime | Storage (CLI) | Storage (Web) |
|-------|------|----------|---------------|---------------|
| Access token | Signed JWT | 3 minutes | `~/.insighta/credentials.json` | HttpOnly cookie |
| Refresh token | Opaque random string | 5 minutes | `~/.insighta/credentials.json` | HttpOnly cookie |

**Rotation.** Every call to `POST /auth/refresh` marks the old refresh token `is_used = TRUE` before issuing a new pair. A used token can never be reused. If a refresh token has already been used when presented, the request is rejected with 401.

**Access token structure:**
```json
{
  "sub": "<user-uuid>",
  "username": "githubhandle",
  "role": "admin",
  "iat": 1720000000,
  "exp": 1720000180
}
```

The `role` field is embedded at issuance time. Every API request resolves RBAC by decoding the token — no extra database query for permission checks.

---

## Role Enforcement Logic

Two roles exist: `admin` and `analyst`. Default for new users: `analyst`.

| Operation | admin | analyst |
|-----------|-------|---------|
| `GET /api/profiles` | ✅ | ✅ |
| `GET /api/profiles/:id` | ✅ | ✅ |
| `GET /api/profiles/search` | ✅ | ✅ |
| `GET /api/profiles/export` | ✅ | ✅ |
| `POST /api/profiles` | ✅ | ❌ 403 |
| `DELETE /api/profiles/:id` | ✅ | ❌ 403 |

**How enforcement works:**

```
middleware.py
  require_auth()      →  decodes JWT, sets g.user_id and g.user_role
  require_role("admin") →  checks g.user_role, returns 403 if not in allowed list
```

Both decorators are stacked on every route that needs protection:

```python
@profiles_bp.route("/profiles", methods=["POST"])
@require_auth          # 401 if no valid token
@require_role("admin") # 403 if role != admin
@require_api_version   # 400 if X-API-Version header missing
@api_rate_limit        # 429 if limit exceeded
def create_profile():
    ...
```

There are no scattered `if user.role == "admin"` checks inside route handlers. All access decisions happen in middleware before handler code runs.

If `is_active = FALSE` on the user record, every authenticated request returns 403 regardless of role.

---

## Natural Language Parsing

`GET /api/profiles/search?q=<query>` accepts plain English descriptions and translates them into structured filters.

**Implemented in `utils.py → parse_nl(q)`**

| Input signal | Extracted filter |
|---|---|
| "male" / "female" (exclusive) | `gender` |
| "child" / "teen" / "adult" / "senior" | `age_group` |
| "young" | `min_age=16, max_age=24` |
| "above N" / "over N" / "older than N" | `min_age=N` |
| "below N" / "under N" / "younger than N" | `max_age=N` |
| "from Nigeria" / "in United States" | `country_id` (mapped via name→ISO lookup) |

Examples:
```
"young males from nigeria"        → gender=male, min_age=16, max_age=24, country_id=NG
"adult females over 30"           → gender=female, age_group=adult, min_age=30
"seniors in united kingdom"       → age_group=senior, country_id=GB
```

If no filters can be extracted, the endpoint returns `400 Unable to interpret query`.

---

## API Reference

All profile endpoints require:
- `Authorization: Bearer <access_token>` **or** `access_token` cookie
- `X-API-Version: 1` header

### Auth endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/github` | Redirect to GitHub OAuth |
| `GET` | `/auth/github/callback` | OAuth callback, issues tokens |
| `POST` | `/auth/cli/exchange` | CLI PKCE token exchange |
| `POST` | `/auth/refresh` | Rotate token pair |
| `POST` | `/auth/logout` | Invalidate refresh token |
| `GET` | `/auth/me` | Current user info |
| `POST` | `/auth/test/token` | Issue test tokens by role (grading use) |

### Profile endpoints

| Method | Path | Auth | Role |
|--------|------|------|------|
| `GET` | `/api/profiles` | ✅ | any |
| `GET` | `/api/profiles/:id` | ✅ | any |
| `GET` | `/api/profiles/search?q=` | ✅ | any |
| `GET` | `/api/profiles/export?format=csv` | ✅ | any |
| `POST` | `/api/profiles` | ✅ | admin |
| `DELETE` | `/api/profiles/:id` | ✅ | admin |

### Paginated response shape

```json
{
  "status": "success",
  "page": 1,
  "limit": 10,
  "total": 2026,
  "total_pages": 203,
  "links": {
    "self": "/api/profiles?page=1&limit=10",
    "next": "/api/profiles?page=2&limit=10",
    "prev": null
  },
  "data": []
}
```

---

## Rate Limiting

| Scope | Limit | Window | Key |
|-------|-------|--------|-----|
| `/auth/*` endpoints | 10 requests | per minute | per IP per endpoint |
| `/api/*` endpoints | 60 requests | per minute | per user per endpoint |

Rate limit keys are scoped **per endpoint** — exhausting the limit on `/auth/github` does not affect `/auth/refresh` or `/auth/logout`. Returns `429 Too Many Requests` with a `Retry-After: 60` header.

---

## Environment Variables

Copy `.env.example` to `.env` and fill in:

```env
DATABASE_URL=postgresql://user:password@host:5432/insighta

GITHUB_CLIENT_ID=your_github_oauth_app_client_id
GITHUB_CLIENT_SECRET=your_github_oauth_app_client_secret
GITHUB_REDIRECT_URI=https://your-backend.railway.app/auth/github/callback

JWT_SECRET=a-long-random-string-minimum-32-chars

FRONTEND_URL=https://your-web-portal.railway.app

FLASK_ENV=production
PORT=5000
```

**GitHub OAuth App setup:**
1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App
2. Homepage URL: your backend URL
3. Authorization callback URL: `https://your-backend.railway.app/auth/github/callback`

---

## Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# edit .env

# Run
python app.py
```

## Deploying to Railway

```bash
# The Procfile handles this automatically:
# web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60

railway login
railway init
railway up
```

Set all environment variables in the Railway dashboard under **Variables**.

---

## Engineering Standards

**Commit format:** `type(scope): message`
```
feat(auth): add github oauth with pkce
feat(profiles): add csv export endpoint
fix(middleware): scope rate limit keys per endpoint
```

**Branch naming:** `feat/`, `fix/`, `chore/`

**PRs:** All changes go through a PR before merging to `main`. CI must pass before merge.

**CI (GitHub Actions on PR to main):**
- Flake8 lint
- Python syntax check on all modules
- Env var documentation check
