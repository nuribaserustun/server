"""
DEWS OCC License Server
Deploy on Render.com (free tier).

Environment variables required:
  LICENSE_SECRET  – shared HMAC secret (must match the value compiled into the client)
"""

import os
import sqlite3
import hmac
import hashlib
import json
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET     = os.environ.get("LICENSE_SECRET", "CHANGE_ME_IN_RENDER_ENV")
TRIAL_DAYS = 30
DB_PATH    = "licenses.db"


# ──────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activations (
            fingerprint   TEXT PRIMARY KEY,
            install_date  TEXT NOT NULL,
            activated_at  TEXT NOT NULL,
            last_seen     TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


# ──────────────────────────────────────────────
# Token helpers
# ──────────────────────────────────────────────

def make_token(payload: dict) -> str:
    """Return base64(json_payload).hmac_hex"""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    b64  = base64.urlsafe_b64encode(body.encode()).decode()
    sig  = hmac.new(SECRET.encode(), b64.encode(), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/activate", methods=["POST"])
def activate():
    data = request.get_json(silent=True)
    if not data or "fp" not in data:
        return jsonify({"error": "missing fingerprint"}), 400

    fp = str(data["fp"])[:128]          # clamp length
    now = datetime.utcnow()
    today = now.strftime("%Y-%m-%d")

    db  = get_db()
    row = db.execute(
        "SELECT install_date FROM activations WHERE fingerprint=?", (fp,)
    ).fetchone()

    if row:
        install_date = row[0]
        db.execute(
            "UPDATE activations SET last_seen=? WHERE fingerprint=?",
            (today, fp)
        )
    else:
        install_date = today
        db.execute(
            "INSERT INTO activations VALUES (?,?,?,?)",
            (fp, install_date, today, today)
        )

    db.commit()
    db.close()

    expiry = (
        datetime.strptime(install_date, "%Y-%m-%d") + timedelta(days=TRIAL_DAYS)
    ).strftime("%Y-%m-%d")

    token = make_token({
        "fp":  fp,
        "iat": install_date,
        "exp": expiry,
        "ts":  today,
    })

    return jsonify({"token": token}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ──────────────────────────────────────────────
# Admin: list activations (protect with a key)
# ──────────────────────────────────────────────

@app.route("/admin/list", methods=["GET"])
def admin_list():
    admin_key = request.headers.get("X-Admin-Key", "")
    if admin_key != os.environ.get("ADMIN_KEY", ""):
        return jsonify({"error": "unauthorized"}), 401

    db   = get_db()
    rows = db.execute(
        "SELECT fingerprint, install_date, activated_at, last_seen FROM activations ORDER BY activated_at DESC"
    ).fetchall()
    db.close()

    result = [
        {"fp": r[0], "install_date": r[1], "activated_at": r[2], "last_seen": r[3]}
        for r in rows
    ]
    return jsonify(result), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
