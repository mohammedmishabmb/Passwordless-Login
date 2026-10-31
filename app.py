import base64
import binascii
import json
import logging
import os
import re
import secrets
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, jsonify, redirect, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import (
    consume_challenge,
    create_user,
    get_user,
    init_database,
    save_challenge,
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("passwordless-auth")

app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    log.warning(
        "SECRET_KEY is not set; using a random key. "
        "Sessions will be invalidated on every restart."
    )
    secret_key = secrets.token_hex(32)

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") != "0",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=16 * 1024,
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

init_database()

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
MIN_KEY_BITS = 2048
MAX_KEY_BITS = 4096


# ---------------------------------------------------------------- helpers

def fail(message, status):
    return jsonify({"success": False, "message": message}), status


def read_username(data):
    """Return a normalized username, or None if it is missing or invalid.

    Rejecting non-strings blocks NoSQL operator injection such as
    {"username": {"$ne": ""}}.
    """
    username = data.get("username")
    if not isinstance(username, str):
        return None
    username = username.strip().lower()
    return username if USERNAME_RE.fullmatch(username) else None


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def load_public_key(jwk):
    """Build an RSA public key from a JWK dict, or raise ValueError."""
    if jwk.get("kty") != "RSA":
        raise ValueError("not an RSA key")
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    if e != 65537 or not MIN_KEY_BITS <= n.bit_length() <= MAX_KEY_BITS:
        raise ValueError("unsupported key parameters")
    return rsa.RSAPublicNumbers(e, n).public_key()


def normalize_public_key(raw):
    """Validate a client supplied JWK string and return a minimal canonical form."""
    if not isinstance(raw, str) or len(raw) > 2048:
        return None
    try:
        jwk = json.loads(raw)
        if not isinstance(jwk, dict):
            return None
        load_public_key(jwk)
        return json.dumps(
            {"kty": "RSA", "n": jwk["n"], "e": jwk["e"]}, sort_keys=True
        )
    except (ValueError, KeyError, TypeError, binascii.Error):
        return None


@app.before_request
def require_json_body():
    if request.method == "POST" and request.path in ("/register", "/challenge", "/verify"):
        if not isinstance(request.get_json(silent=True), dict):
            return fail("Invalid request", 400)


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ------------------------------------------------------------------ pages

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/recover")
def recover_page():
    return render_template("recover.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


# -------------------------------------------------------------------- API

@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    username = read_username(data)
    public_key = normalize_public_key(data.get("public_key"))

    if not username:
        return fail("Username must be 3-32 characters: letters, numbers, . _ -", 400)
    if not public_key:
        return fail("Invalid public key", 400)
    if not create_user(username, public_key):
        return fail("Username already exists", 409)

    return jsonify({"success": True, "message": "Registration successful"})


@app.route("/challenge", methods=["POST"])
@limiter.limit("10 per minute")
def challenge():
    username = read_username(request.get_json())
    if not username:
        return fail("Invalid username", 400)

    value = secrets.token_urlsafe(32)
    # Unknown users get an identical response so usernames cannot be probed here.
    if get_user(username):
        save_challenge(username, value)

    return jsonify({"success": True, "challenge": value})


@app.route("/verify", methods=["POST"])
@limiter.limit("10 per minute")
def verify():
    data = request.get_json()
    username = read_username(data)
    signature_b64 = data.get("signature")

    if not username or not isinstance(signature_b64, str) or len(signature_b64) > 2048:
        return fail("Authentication failed", 400)

    # Always consume the challenge: it is single use, pass or fail.
    challenge_value = consume_challenge(username)
    user = get_user(username)
    if not challenge_value or not user:
        return fail("Authentication failed", 401)

    try:
        public_key = load_public_key(json.loads(user["public_key"]))
        public_key.verify(
            base64.b64decode(signature_b64, validate=True),
            challenge_value.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, KeyError, TypeError, binascii.Error):
        return fail("Authentication failed", 401)

    session.clear()  # prevents session fixation
    session["username"] = username
    session.permanent = True
    return jsonify({"success": True, "message": "Authentication successful"})


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
