"""
TokenForge — JWT Lab
Three flags covering alg:none bypass, weak secret brute-force, and kid header injection.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import tempfile
import textwrap
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for

app = Flask(__name__)

# ── flags ──────────────────────────────────────────────────────────────────────
FLAG1 = os.environ.get("FLAG1", "FLAG{4lg_n0n3_trus7_n0_0ne}")
FLAG2 = os.environ.get("FLAG2", "FLAG{w34k_s3cr3t_cr4ck3d_l1k3_4n_egg}")
FLAG3 = os.environ.get("FLAG3", "FLAG{k1d_1nj3ct10n_sq1_g0es_brr}")

# ── weak signing secret (challenge 2) ─────────────────────────────────────────
WEAK_SECRET = "password123"

# ── accounts ───────────────────────────────────────────────────────────────────
USERS = {
    "alice": {"password": "hunter2", "role": "user"},
    "admin": {"password": "REDACTED", "role": "admin"},
}

# ── pure-Python JWT helpers (no library — intentionally vulnerable) ────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)

def _make_jwt(payload: dict, secret: str | None = None, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if alg == "none" or secret is None:
        sig = ""
    else:
        sig = _b64url_encode(
            hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        )
    return f"{h}.{p}.{sig}"

def _decode_jwt_unsafe(token: str) -> tuple[dict, dict]:
    """Decode WITHOUT verifying signature — returns (header, payload)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload

def _verify_jwt_challenge1(token: str) -> dict:
    """
    Challenge 1 — alg:none bypass.
    Bug: trusts whatever algorithm the header declares.
    """
    header, payload = _decode_jwt_unsafe(token)
    alg = header.get("alg", "").lower()
    if alg == "none":
        # 🐛 no signature check — just trust the payload
        return payload
    elif alg == "hs256":
        parts = token.split(".")
        expected = _b64url_encode(
            hmac.new(WEAK_SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(parts[2], expected):
            raise ValueError("bad signature")
        return payload
    else:
        raise ValueError(f"unsupported algorithm: {alg}")

def _verify_jwt_challenge2(token: str) -> dict:
    """
    Challenge 2 — weak secret.
    Correctly enforces HS256, but uses a weak secret.
    """
    header, payload = _decode_jwt_unsafe(token)
    if header.get("alg") != "HS256":
        raise ValueError("only HS256 accepted")
    parts = token.split(".")
    expected = _b64url_encode(
        hmac.new(WEAK_SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(parts[2], expected):
        raise ValueError("bad signature")
    return payload

def _verify_jwt_challenge3(token: str) -> dict:
    """
    Challenge 3 — kid header SQL injection.
    Uses the 'kid' (key ID) field to look up the signing key from a SQLite DB.
    Bug: kid is interpolated directly into a SQL query.
    """
    header, payload = _decode_jwt_unsafe(token)
    if header.get("alg") != "HS256":
        raise ValueError("only HS256 accepted")

    kid = header.get("kid", "default")

    # Set up an in-memory DB with one key record
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE keys (id TEXT, secret TEXT)")
    db.execute("INSERT INTO keys VALUES ('default', 'super-secret-key-ch3')")
    db.commit()

    # 🐛 kid is NOT parameterised
    row = db.execute(f"SELECT secret FROM keys WHERE id = '{kid}'").fetchone()  # noqa: S608
    if row is None:
        raise ValueError("unknown key id")

    secret = row[0]
    parts = token.split(".")
    expected = _b64url_encode(
        hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(parts[2], expected):
        raise ValueError("bad signature")
    return payload

# ── routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# ── challenge 1: alg:none ──────────────────────────────────────────────────────

@app.route("/c1/login", methods=["GET", "POST"])
def c1_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and user["password"] == password:
            token = _make_jwt({"sub": username, "role": user["role"]}, secret=WEAK_SECRET)
            return render_template("c1_login.html", token=token, logged_in=True, username=username)
        error = "Invalid credentials."
    return render_template("c1_login.html", error=error)

@app.route("/c1/admin")
def c1_admin():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        token = request.args.get("token", "")
    if not token:
        return render_template("c1_admin.html", error="No token provided. Add ?token=<jwt> or Authorization: Bearer <jwt>.")
    try:
        payload = _verify_jwt_challenge1(token)
    except Exception as exc:
        return render_template("c1_admin.html", error=f"Token rejected: {exc}")
    if payload.get("role") != "admin":
        return render_template("c1_admin.html", error=f"Access denied. Your role: {payload.get('role', 'none')}")
    return render_template("c1_admin.html", flag=FLAG1, payload=payload)

# ── challenge 2: weak secret ───────────────────────────────────────────────────

@app.route("/c2/login", methods=["GET", "POST"])
def c2_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and user["password"] == password:
            token = _make_jwt({"sub": username, "role": user["role"]}, secret=WEAK_SECRET)
            return render_template("c2_login.html", token=token, logged_in=True, username=username)
        error = "Invalid credentials."
    return render_template("c2_login.html", error=error)

@app.route("/c2/admin")
def c2_admin():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        token = request.args.get("token", "")
    if not token:
        return render_template("c2_admin.html", error="No token provided.")
    try:
        payload = _verify_jwt_challenge2(token)
    except Exception as exc:
        return render_template("c2_admin.html", error=f"Token rejected: {exc}")
    if payload.get("role") != "admin":
        return render_template("c2_admin.html", error=f"Access denied. Your role: {payload.get('role', 'none')}")
    return render_template("c2_admin.html", flag=FLAG2, payload=payload)

# ── challenge 3: kid injection ─────────────────────────────────────────────────

@app.route("/c3/login", methods=["GET", "POST"])
def c3_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and user["password"] == password:
            # Issues a properly signed token with kid: default
            header_override = {"alg": "HS256", "typ": "JWT", "kid": "default"}
            h = _b64url_encode(json.dumps(header_override, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps({"sub": username, "role": user["role"]}, separators=(",", ":")).encode())
            sig = _b64url_encode(
                hmac.new(b"super-secret-key-ch3", f"{h}.{p}".encode(), hashlib.sha256).digest()
            )
            token = f"{h}.{p}.{sig}"
            return render_template("c3_login.html", token=token, logged_in=True, username=username)
        error = "Invalid credentials."
    return render_template("c3_login.html", error=error)

@app.route("/c3/admin")
def c3_admin():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        token = request.args.get("token", "")
    if not token:
        return render_template("c3_admin.html", error="No token provided.")
    try:
        payload = _verify_jwt_challenge3(token)
    except Exception as exc:
        return render_template("c3_admin.html", error=f"Token rejected: {exc}")
    if payload.get("role") != "admin":
        return render_template("c3_admin.html", error=f"Access denied. Your role: {payload.get('role', 'none')}")
    return render_template("c3_admin.html", flag=FLAG3, payload=payload)

# ── debug: decode any token ────────────────────────────────────────────────────

@app.route("/decode", methods=["GET", "POST"])
def decode():
    result = None
    error = None
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        try:
            header, payload = _decode_jwt_unsafe(token)
            parts = token.split(".")
            result = {
                "header": header,
                "payload": payload,
                "signature": parts[2] if len(parts) == 3 else "",
            }
        except Exception as exc:
            error = str(exc)
    return render_template("decode.html", result=result, error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=False)
