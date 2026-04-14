"""
DEWS OCC License Server
Deploy on Render.com (free tier).

Environment variables required:
  LICENSE_SECRET  – shared HMAC secret (must match the value compiled into the client)
  ADMIN_KEY       – secret header value for admin endpoints
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
            last_seen     TEXT NOT NULL,
            blocked       INTEGER NOT NULL DEFAULT 0,
            block_reason  TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip            TEXT PRIMARY KEY,
            blocked_at    TEXT NOT NULL,
            reason        TEXT NOT NULL DEFAULT ''
        )
    """)
    # migrate: add columns if upgrading from old schema
    for col, definition in [("blocked", "INTEGER NOT NULL DEFAULT 0"),
                             ("block_reason", "TEXT NOT NULL DEFAULT ''")]:
        try:
            conn.execute(f"ALTER TABLE activations ADD COLUMN {col} {definition}")
        except Exception:
            pass
    conn.commit()
    return conn


# ──────────────────────────────────────────────
# Auth helper
# ──────────────────────────────────────────────

def require_admin():
    key = request.headers.get("X-Admin-Key", "")
    if key != os.environ.get("ADMIN_KEY", ""):
        return jsonify({"error": "unauthorized"}), 401
    return None


# ──────────────────────────────────────────────
# IP block guard (runs before every request)
# ──────────────────────────────────────────────

@app.before_request
def check_ip_block():
    ip = request.remote_addr
    db = get_db()
    row = db.execute("SELECT reason FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
    db.close()
    if row:
        return jsonify({"error": "access denied"}), 403


# ──────────────────────────────────────────────
# Token helpers
# ──────────────────────────────────────────────

def make_token(payload: dict) -> str:
    """Return base64url(json_payload).hmac_hex"""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    b64  = base64.urlsafe_b64encode(body.encode()).decode()
    sig  = hmac.new(SECRET.encode(), b64.encode(), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


# ──────────────────────────────────────────────
# Activate
# ──────────────────────────────────────────────

@app.route("/activate", methods=["POST"])
def activate():
    data = request.get_json(silent=True)
    if not data or "fp" not in data:
        return jsonify({"error": "missing fingerprint"}), 400

    fp    = str(data["fp"])[:128]
    today = datetime.utcnow().strftime("%Y-%m-%d")

    db  = get_db()
    row = db.execute(
        "SELECT install_date, blocked, block_reason FROM activations WHERE fingerprint=?",
        (fp,)
    ).fetchone()

    if row:
        install_date, blocked, block_reason = row
        if blocked:
            db.close()
            return jsonify({"error": f"license revoked: {block_reason}"}), 403
        db.execute(
            "UPDATE activations SET last_seen=? WHERE fingerprint=?",
            (today, fp)
        )
    else:
        install_date = today
        db.execute(
            "INSERT INTO activations (fingerprint, install_date, activated_at, last_seen) VALUES (?,?,?,?)",
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


# ──────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ──────────────────────────────────────────────
# Admin: list all activations
# ──────────────────────────────────────────────

@app.route("/admin/list", methods=["GET"])
def admin_list():
    err = require_admin()
    if err: return err

    db   = get_db()
    rows = db.execute(
        "SELECT fingerprint, install_date, activated_at, last_seen, blocked, block_reason "
        "FROM activations ORDER BY activated_at DESC"
    ).fetchall()
    db.close()

    return jsonify([
        {
            "fp":           r[0],
            "install_date": r[1],
            "activated_at": r[2],
            "last_seen":    r[3],
            "blocked":      bool(r[4]),
            "block_reason": r[5],
        }
        for r in rows
    ]), 200


# ──────────────────────────────────────────────
# Admin: block / unblock a device (fingerprint)
# ──────────────────────────────────────────────

@app.route("/admin/block/device", methods=["POST"])
def admin_block_device():
    err = require_admin()
    if err: return err

    data   = request.get_json(silent=True) or {}
    fp     = str(data.get("fp", ""))[:128]
    reason = str(data.get("reason", "blocked by admin"))[:256]

    if not fp:
        return jsonify({"error": "fp required"}), 400

    db = get_db()
    db.execute(
        "UPDATE activations SET blocked=1, block_reason=? WHERE fingerprint=?",
        (reason, fp)
    )
    db.commit()
    db.close()
    return jsonify({"ok": True, "fp": fp, "reason": reason}), 200


@app.route("/admin/unblock/device", methods=["POST"])
def admin_unblock_device():
    err = require_admin()
    if err: return err

    data = request.get_json(silent=True) or {}
    fp   = str(data.get("fp", ""))[:128]

    if not fp:
        return jsonify({"error": "fp required"}), 400

    db = get_db()
    db.execute(
        "UPDATE activations SET blocked=0, block_reason='' WHERE fingerprint=?",
        (fp,)
    )
    db.commit()
    db.close()
    return jsonify({"ok": True, "fp": fp}), 200


# ──────────────────────────────────────────────
# Admin: block / unblock an IP address
# ──────────────────────────────────────────────

@app.route("/admin/block/ip", methods=["POST"])
def admin_block_ip():
    err = require_admin()
    if err: return err

    data   = request.get_json(silent=True) or {}
    ip     = str(data.get("ip", ""))[:64]
    reason = str(data.get("reason", "blocked by admin"))[:256]

    if not ip:
        return jsonify({"error": "ip required"}), 400

    today = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason) VALUES (?,?,?)",
        (ip, today, reason)
    )
    db.commit()
    db.close()
    return jsonify({"ok": True, "ip": ip, "reason": reason}), 200


@app.route("/admin/unblock/ip", methods=["POST"])
def admin_unblock_ip():
    err = require_admin()
    if err: return err

    data = request.get_json(silent=True) or {}
    ip   = str(data.get("ip", ""))[:64]

    if not ip:
        return jsonify({"error": "ip required"}), 400

    db = get_db()
    db.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    db.commit()
    db.close()
    return jsonify({"ok": True, "ip": ip}), 200


@app.route("/admin/list/blocked-ips", methods=["GET"])
def admin_list_blocked_ips():
    err = require_admin()
    if err: return err

    db   = get_db()
    rows = db.execute(
        "SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    db.close()

    return jsonify([
        {"ip": r[0], "blocked_at": r[1], "reason": r[2]}
        for r in rows
    ]), 200


# ──────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
