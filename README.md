# Passwordless Authentication

A passwordless login system built on public-key cryptography. Users never create or type a password. Their browser generates an RSA key pair, the **private key stays in the browser**, and the server stores only the **public key**. To log in, the server sends a random challenge, the browser signs it with the private key, and the server verifies the signature.

**Stack:** Python · Flask · MongoDB · Web Crypto API (RSA-PSS, SHA-256) · IndexedDB

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [Requirements](#requirements)
5. [Installation and Running](#installation-and-running)
6. [Configuration](#configuration)
7. [Using the Application](#using-the-application)
8. [API Reference](#api-reference)
9. [Production Deployment](#production-deployment)
10. [Limitations and Threat Model](#limitations-and-threat-model)
11. [Testing](#testing)
12. [Troubleshooting](#troubleshooting)

---

## How It Works

### Registration

```
Browser                                         Server
   |  1. Generate RSA-PSS 2048-bit key pair        |
   |  2. POST /register {username, public_key} --->|  validate username + key, store public key
   |  3. Save non-extractable private key          |
   |     in IndexedDB                              |
   |  4. Offer one-time PEM backup download        |
```

Only after the server accepts the registration is anything written to the browser, so a failed or duplicate registration can never overwrite an existing key.

### Login

```
Browser                                         Server
   |  1. Load private key from IndexedDB           |
   |  2. POST /challenge {username} -------------->|  random 256-bit challenge, valid 60 s
   |  3. Sign challenge (RSA-PSS, salt 32)         |
   |  4. POST /verify {username, signature} ------>|  consume challenge, verify with public key
   |  <--------------- session cookie -------------|  start session
```

### Recovery

If browser data is deleted, the user uploads the PEM backup downloaded at registration. The browser imports it as a non-extractable key, proves ownership by signing a fresh challenge (same `/challenge` and `/verify` flow as login), and only then stores the key again.

---

## Features

- No passwords to leak, phish, reuse or brute-force
- Private key is generated client-side and never sent to the server
- Single-use, short-lived challenges prevent replay
- Account recovery from a private-key backup file
- Rate limiting, strict Content-Security-Policy and hardened session cookies
- Small codebase: about 550 lines across the backend and frontend

---

## Project Structure

```
passwordless-auth/
├── app.py              # Flask app: routes, validation, signature verification, security headers
├── database.py         # MongoDB access: users, challenges, indexes
├── requirements.txt    # Pinned Python dependencies
├── .env.example        # Example environment variables
├── README.md
├── static/
│   ├── app.js          # Client-side crypto: key generation, signing, IndexedDB, recovery
│   └── style.css
└── templates/
    ├── index.html      # Home
    ├── register.html   # Create account + key backup
    ├── login.html
    ├── recover.html    # Restore account from PEM backup
    └── dashboard.html  # Authenticated page
```

### MongoDB collections

| Collection | Fields | Indexes |
|---|---|---|
| `users` | `username`, `public_key` (JSON string, JWK `kty`/`n`/`e`) | unique on `username` |
| `challenges` | `username`, `challenge`, `expires_at` | unique on `username`; TTL on `expires_at` |

---

## Requirements

- Python 3.10 or newer
- MongoDB 5.0 or newer, running and reachable
- A modern browser with Web Crypto and IndexedDB (Chrome, Edge, Firefox, Safari)
- HTTPS in production. Browsers expose Web Crypto only in secure contexts; `http://localhost` is treated as secure.

Python dependencies (`requirements.txt`):

| Package | Purpose |
|---|---|
| Flask | Web framework |
| Flask-Limiter | Rate limiting |
| cryptography | RSA-PSS signature verification |
| pymongo | MongoDB driver |

---

## Installation and Running

### 1. Start MongoDB

```bash
# Local install
mongod

# or with Docker
docker run -d --name mongo -p 27017:27017 mongo:7
```

### 2. Install the app

```bash
cd passwordless-auth
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure

```bash
# macOS / Linux
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Windows PowerShell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

Other settings are optional. See [Configuration](#configuration).

### 4. Run

```bash
python app.py
```

Open <http://localhost:5000>.

For development with auto-reload and the debugger, set `FLASK_DEBUG=1`. Never do this on a public server.

---

## Configuration

All settings are environment variables. `.env.example` lists them; the app does not load `.env` files by itself, so export them or use your process manager.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | random per start | Signs session cookies. **Set this** to a long random value. If unset, a random key is generated and all sessions are lost on restart (and differ between workers). |
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string. |
| `MONGO_DB` | `passwordless_auth` | Database name. |
| `COOKIE_SECURE` | `1` | Marks the session cookie `Secure`. Set to `0` only if your browser refuses the cookie over plain-HTTP localhost (some Safari versions). |
| `RATELIMIT_STORAGE_URI` | `memory://` | Rate-limit storage. Use e.g. `redis://localhost:6379` with multiple workers. |
| `FLASK_DEBUG` | off | `1` enables Flask debug mode for local development only. |

Constants you can change in code:

| Setting | File | Default |
|---|---|---|
| Challenge lifetime | `database.py` `CHALLENGE_TTL_SECONDS` | 60 s |
| Session lifetime | `app.py` `PERMANENT_SESSION_LIFETIME` | 30 min |
| Allowed key size | `app.py` `MIN_KEY_BITS` / `MAX_KEY_BITS` | 2048 / 4096 |
| Rate limits | `app.py` `@limiter.limit(...)` | see above |

---

## Using the Application

1. **Create account** (`/register`): enter a username. The browser generates your key pair and registers the public key.
2. **Download the backup** immediately. The button appears once, and the key is cleared from memory after download. Store the `.pem` file somewhere safe, such as a password manager or encrypted drive.
3. **Log in** (`/login`): enter your username. The browser signs the challenge automatically.
4. **Recover** (`/recover`): on a new browser or after clearing site data, enter your username and upload the `.pem` backup.
5. **Log out** from the dashboard.

Usernames are case-insensitive and stored in lowercase.

---

## API Reference

All `POST` endpoints under this section require `Content-Type: application/json` and a JSON object body. Responses are JSON with `success` and `message`, unless noted.

### Pages (HTML)

| Method | Path | Description |
|---|---|---|
| GET | `/` | Home |
| GET | `/register` | Registration page |
| GET | `/login` | Login page |
| GET | `/recover` | Recovery page |
| GET | `/dashboard` | Authenticated page; redirects to `/login` without a session |
| POST | `/logout` | Ends the session and redirects to `/` |

### `POST /register`

Request:

```json
{ "username": "alice", "public_key": "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}" }
```

`public_key` is the JWK exported by Web Crypto, serialized as a string.

| Status | Meaning |
|---|---|
| 200 | Registered |
| 400 | Invalid username, or invalid/weak public key |
| 409 | Username already exists |
| 429 | Rate limited |

### `POST /challenge`

Request: `{ "username": "alice" }`

Response: `{ "success": true, "challenge": "<43-char url-safe token>" }`

The challenge is valid for 60 seconds and for one verification attempt. Unknown usernames receive an identical-looking response (no challenge is stored).

### `POST /verify`

Request:

```json
{ "username": "alice", "signature": "<base64 RSA-PSS signature of the challenge string>" }
```

Signature parameters: RSA-PSS, MGF1 with SHA-256, SHA-256 digest, salt length 32, over the UTF-8 bytes of the challenge.

| Status | Meaning |
|---|---|
| 200 | Authenticated; session cookie set |
| 400 | Malformed request |
| 401 | Authentication failed (unknown user, missing/expired/used challenge, or bad signature, all reported identically) |
| 429 | Rate limited |

---

## Production Deployment

1. **Use HTTPS** (terminate TLS at a reverse proxy such as Nginx or Caddy) and keep `COOKIE_SECURE=1`.
2. **Set `SECRET_KEY`** from a secrets manager. The same value must be used by every worker.
3. **Use a WSGI server**, not `python app.py`:
   ```bash
   gunicorn -w 4 -b 127.0.0.1:8000 app:app
   ```
4. **Shared rate limiting:** set `RATELIMIT_STORAGE_URI=redis://...`, otherwise each worker counts separately.
5. **Behind a proxy**, make the app see real client IPs for rate limiting by adding to `app.py`:
   ```python
   from werkzeug.middleware.proxy_fix import ProxyFix
   app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
   ```
   Only do this when you actually run behind exactly one trusted proxy.
6. **Secure MongoDB:** enable authentication, bind to a private interface, use TLS, and put credentials in `MONGO_URI`.
7. Keep dependencies updated and re-run `pip list --outdated` regularly.

---

## Limitations and Threat Model

What this design protects against: password theft, credential stuffing, phishing of reusable secrets, server database leaks (only public keys are stored), and replay of captured login traffic.

What it does **not** protect against, and what to consider next:

- **Malware or XSS on the user's device.** A non-extractable key cannot be copied, but code running in the page can still ask the browser to sign. The strict CSP reduces this risk but does not remove it.
- **No multi-device support.** Each browser needs its own recovery import; there is no way to add a second key to an account.
- **No account recovery without the backup.** Lose both the browser data and the PEM file, and the account is unrecoverable by design.
- **Username enumeration at registration.** The "already exists" response reveals taken names.
- **No email or admin controls,** no account deletion, no key rotation, no audit log.
- **No origin binding.** Unlike WebAuthn/passkeys, signatures are not bound to the site origin, so this scheme does not resist a malicious site that tricks a user's browser into signing, if it could access the key. For high-assurance systems, consider WebAuthn.

---

## Testing

The project ships without a test suite. A quick manual check:

1. Register a user and download the backup.
2. Log in, then log out.
3. Register the same username again (expect "Username already exists", and login must still work afterwards).
4. Open a private window, try to log in (expect "Private key not found in this browser"), then recover with the PEM file.
5. Try `curl -X POST localhost:5000/challenge -H 'Content-Type: application/json' -d '{"username":{"$ne":""}}'` and confirm a 400 response.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ServerSelectionTimeoutError` on start | MongoDB is not running or `MONGO_URI` is wrong. |
| Login works, but `/dashboard` redirects back to login | The browser rejected the `Secure` cookie over plain HTTP. Use `localhost`, HTTPS, or set `COOKIE_SECURE=0` for local testing. |
| Sessions end after every restart | `SECRET_KEY` is not set. |
| `crypto.subtle` is undefined | The page is not in a secure context. Use HTTPS or `http://localhost`. |
| "Private key not found in this browser" | Site data was cleared or you are on a different browser. Use **Recover** with your PEM backup. |
| "Authentication failed" | Wrong key for that account, challenge expired (60 s), or the username does not exist. |
| HTTP 429 | Rate limit hit. Wait a minute. |
| Inline scripts or styles you added do not run | The CSP blocks them. Put code in `static/` files. |
