"""
RequestRelay — SSRF Lab
Four flags covering basic SSRF, metadata endpoint, blind SSRF, and filter bypass.
"""
import os
import re
import socket
import threading
import urllib.parse
from datetime import datetime

import requests
from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

app = Flask(__name__)

# ── flags ──────────────────────────────────────────────────────────────────────
FLAG1 = os.environ.get("FLAG1", "FLAG{b4s1c_ssrf_s3rv3r_s1d3_r3qu3st}")
FLAG2 = os.environ.get("FLAG2", "FLAG{m3t4d4t4_3ndb0x_1m4g1n3_aws}")
FLAG3 = os.environ.get("FLAG3", "FLAG{bl1nd_ssrf_y0u_c4nt_s33_m3}")
FLAG4 = os.environ.get("FLAG4", "FLAG{byp4ss_bl0ck_1p_f1lt3r}")

# ── blind SSRF callback log (in-memory) ───────────────────────────────────────
BLIND_LOG: list[dict] = []

# ── filter helpers ─────────────────────────────────────────────────────────────
BLOCKLIST_LITERALS = {"127.0.0.1", "localhost", "::1"}


def is_blocked_literal(url: str) -> bool:
    """Flag 4's naive filter: blocks only the string literals, not all forms."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    return host.lower() in BLOCKLIST_LITERALS


def safe_fetch(url: str, timeout: float = 3.0) -> requests.Response:
    """Fetch with no redirect following so SSRF chains are easier to reason about."""
    return requests.get(url, timeout=timeout, allow_redirects=False)


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC-FACING APP ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ── Challenge 1: Basic SSRF ────────────────────────────────────────────────────
@app.route("/fetch")
def fetch():
    """
    A simple 'URL preview' feature. Supply ?url= and the server fetches it and
    shows you the response body. The flag lives at an internal-only endpoint.
    """
    url = request.args.get("url", "")
    if not url:
        return render_template("fetch.html", result=None, url="")
    try:
        resp = safe_fetch(url)
        body = resp.text[:4000]
    except Exception as e:
        body = f"[error] {e}"
    return render_template("fetch.html", result=body, url=url)


# ── Challenge 2: Cloud metadata simulation ────────────────────────────────────
@app.route("/avatar")
def avatar():
    """
    Profile avatar loader. Accepts ?image_url= and renders the image server-side
    (simulating a service that proxies images). The 'cloud metadata' endpoint
    is simulated on 127.42.42.42 (a loopback alias) — see the lab README for
    how to set that up, or the lab runs a fake metadata thread on port 5042.
    """
    image_url = request.args.get("image_url", "")
    if not image_url:
        return render_template("avatar.html", result=None, url="")
    try:
        resp = safe_fetch(image_url)
        body = resp.text[:2000]
    except Exception as e:
        body = f"[error] {e}"
    return render_template("avatar.html", result=body, url=image_url)


# ── Challenge 3: Blind SSRF ───────────────────────────────────────────────────
@app.route("/webhook/register", methods=["GET", "POST"])
def webhook_register():
    """
    Webhook registration: 'Tell us your callback URL and we'll ping it when
    an event fires.' The app really does fetch the URL you give — but it
    shows you nothing. Prove it happened via the /webhook/log endpoint.
    """
    if request.method == "POST":
        callback_url = request.form.get("callback_url", "")
        entry = {
            "time": datetime.utcnow().isoformat() + "Z",
            "callback_url": callback_url,
            "fetched": False,
            "response_snippet": "",
        }
        try:
            resp = safe_fetch(callback_url)
            entry["fetched"] = True
            entry["response_snippet"] = resp.text[:200]
        except Exception as e:
            entry["response_snippet"] = f"[error] {e}"
        BLIND_LOG.append(entry)
        return render_template("webhook.html", registered=True, url=callback_url)
    return render_template("webhook.html", registered=False, url="")


@app.route("/webhook/log")
def webhook_log():
    """Shows what the server actually fetched — the 'attacker sees' side."""
    return render_template("webhook_log.html", entries=list(reversed(BLIND_LOG[-20:])))


# ── Challenge 4: Filter bypass ────────────────────────────────────────────────
@app.route("/export")
def export():
    """
    Export feature with a 'security fix': blocks 127.0.0.1 and localhost.
    But the filter only checks the literal string — bypass it.
    Flag lives at /internal/secret (same as challenge 1).
    """
    url = request.args.get("url", "")
    if not url:
        return render_template("export.html", result=None, url="", blocked=False)
    if is_blocked_literal(url):
        return render_template(
            "export.html",
            result=None,
            url=url,
            blocked=True,
            block_msg="Blocked: internal addresses are not allowed.",
        )
    try:
        resp = safe_fetch(url)
        body = resp.text[:4000]
    except Exception as e:
        body = f"[error] {e}"
    return render_template("export.html", result=body, url=url, blocked=False)


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL-ONLY ROUTES  (the flag is here — only the server itself should reach it)
# ══════════════════════════════════════════════════════════════════════════════

def _is_local(req: "request") -> bool:  # type: ignore[name-defined]
    """True only when the request comes from loopback."""
    remote = req.remote_addr or ""
    return remote in ("127.0.0.1", "::1", "0.0.0.0") or remote.startswith("127.")


@app.route("/internal/secret")
def internal_secret():
    if not _is_local(request):
        abort(403)
    return f"INTERNAL SYSTEM — {FLAG1}\n"


# ── Fake cloud metadata server (simulated on port 5042, started in a thread) ──
def _run_metadata_server():
    """
    Simulates http://169.254.169.254/ on localhost:5042.
    In the challenge, players redirect the /avatar endpoint to
    http://127.0.0.1:5042/latest/meta-data/iam/security-credentials/lab-role
    """
    meta_app = Flask("metadata")

    @meta_app.route("/latest/meta-data/")
    def meta_index():
        return "ami-id\niam/\nhostname\n"

    @meta_app.route("/latest/meta-data/iam/")
    def meta_iam():
        return "security-credentials/\n"

    @meta_app.route("/latest/meta-data/iam/security-credentials/")
    def meta_creds_list():
        return "lab-role\n"

    @meta_app.route("/latest/meta-data/iam/security-credentials/lab-role")
    def meta_creds():
        return jsonify({
            "Code": "Success",
            "Type": "AWS-HMAC",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": FLAG2,
            "Expiration": "2099-01-01T00:00:00Z",
        })

    meta_app.run(host="127.0.0.1", port=5042, use_reloader=False, threaded=True)


# ── Blind SSRF callback target (simulated "attacker's server") ────────────────
def _run_callback_server():
    """
    Simulates http://127.0.0.1:5043/ — the 'attacker-controlled server'
    that proves blind SSRF. When the main app fetches this, it logs the hit
    AND returns FLAG3 so the webhook log reveals the flag.
    """
    cb_app = Flask("callback")

    @cb_app.route("/", defaults={"path": ""})
    @cb_app.route("/<path:path>")
    def catch_all(path):
        return f"HIT — your blind SSRF worked!\n{FLAG3}\n"

    cb_app.run(host="127.0.0.1", port=5043, use_reloader=False, threaded=True)


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    threading.Thread(target=_run_metadata_server, daemon=True).start()
    threading.Thread(target=_run_callback_server, daemon=True).start()
    app.run(host="0.0.0.0", port=5008, debug=False)
