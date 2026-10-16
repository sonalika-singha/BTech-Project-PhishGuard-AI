"""
Lightweight JWT authentication + per-user history for PhishGuard AI.

No external database and no Firebase — users and history are stored in simple
JSON files on disk. Passwords are salted + hashed with the Python standard
library (hashlib.pbkdf2_hmac). Tokens are signed JWTs (PyJWT).

Exposes a Flask Blueprint `auth_bp` with:
    POST /auth/register   {username, password}        -> {token, username}
    POST /auth/login      {username, password}        -> {token, username}
    GET  /auth/me         (Bearer token)              -> {username}
    GET  /history         (Bearer token)              -> {history: [...]}
    POST /history         (Bearer token) {entry...}   -> {ok: true}
    DELETE /history       (Bearer token)              -> {ok: true}   (clears)

and a helper `current_user()` that returns the username for the request's
Bearer token (or None), plus `log_history(username, entry)` used by the
analysis routes to record a scan.
"""

import os
import json
import time
import hmac
import hashlib
import secrets
import functools

import jwt  # PyJWT
from flask import Blueprint, request, jsonify

# ─────────────────────────────────────────
# Config / storage paths
# ─────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_HERE, "user_data")
os.makedirs(_DATA_DIR, exist_ok=True)

_USERS_FILE = os.path.join(_DATA_DIR, "users.json")
_HISTORY_FILE = os.path.join(_DATA_DIR, "history.json")

# Secret key for signing tokens. In production set PHISHGUARD_SECRET in the
# environment; otherwise a persistent random key is generated and stored.
_SECRET_FILE = os.path.join(_DATA_DIR, ".secret")


def _load_secret():
    env = os.environ.get("PHISHGUARD_SECRET")
    if env:
        return env
    try:
        with open(_SECRET_FILE, "r") as f:
            s = f.read().strip()
            if s:
                return s
    except Exception:
        pass
    s = secrets.token_hex(32)
    try:
        with open(_SECRET_FILE, "w") as f:
            f.write(s)
    except Exception:
        pass
    return s


_SECRET = _load_secret()
_ALGO = "HS256"
_TOKEN_TTL = 7 * 24 * 3600  # 7 days

auth_bp = Blueprint("auth", __name__)


# ─────────────────────────────────────────
# Tiny JSON helpers (load/save)
# ─────────────────────────────────────────
def _read_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


# ─────────────────────────────────────────
# Password hashing (stdlib, pbkdf2)
# ─────────────────────────────────────────
def _hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), 120_000)
    return salt, dk.hex()


def _verify_password(password, salt, expected_hex):
    _, test_hex = _hash_password(password, salt)
    return hmac.compare_digest(test_hex, expected_hex)


# ─────────────────────────────────────────
# Token helpers
# ─────────────────────────────────────────
def _make_token(username):
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + _TOKEN_TTL}
    return jwt.encode(payload, _SECRET, algorithm=_ALGO)


def _decode_token(token):
    try:
        data = jwt.decode(token, _SECRET, algorithms=[_ALGO])
        return data.get("sub")
    except Exception:
        return None


def current_user():
    """Return the username for the request's Bearer token, or None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return _decode_token(auth[7:].strip())


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        return fn(user, *args, **kwargs)
    return wrapper


# ─────────────────────────────────────────
# History storage (per user)
# ─────────────────────────────────────────
_MAX_HISTORY = 200  # keep the most recent N entries per user


def log_history(username, entry):
    """Append a scan entry to a user's history. Safe no-op if no user."""
    if not username:
        return
    try:
        store = _read_json(_HISTORY_FILE, {})
        items = store.get(username, [])
        entry = dict(entry)
        entry.setdefault("time", int(time.time()))
        items.insert(0, entry)  # newest first
        store[username] = items[:_MAX_HISTORY]
        _write_json(_HISTORY_FILE, store)
    except Exception:
        pass


def get_history(username):
    store = _read_json(_HISTORY_FILE, {})
    return store.get(username, [])


def clear_history(username):
    store = _read_json(_HISTORY_FILE, {})
    if username in store:
        store[username] = []
        _write_json(_HISTORY_FILE, store)


# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────
def _valid_username(u):
    return isinstance(u, str) and 3 <= len(u) <= 32 and all(
        c.isalnum() or c in "._-" for c in u)


@auth_bp.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not _valid_username(username):
        return jsonify({"error": "Username must be 3-32 chars (letters, digits, . _ -)"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    users = _read_json(_USERS_FILE, {})
    if username.lower() in {k.lower() for k in users}:
        return jsonify({"error": "Username already taken"}), 409

    salt, pw_hash = _hash_password(password)
    users[username] = {"salt": salt, "hash": pw_hash, "created": int(time.time())}
    _write_json(_USERS_FILE, users)
    return jsonify({"token": _make_token(username), "username": username})


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    users = _read_json(_USERS_FILE, {})
    # case-insensitive username match
    match = None
    for u in users:
        if u.lower() == username.lower():
            match = u
            break
    if not match or not _verify_password(password, users[match]["salt"], users[match]["hash"]):
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({"token": _make_token(match), "username": match})


@auth_bp.route("/auth/me", methods=["GET"])
@login_required
def me(user):
    return jsonify({"username": user})


@auth_bp.route("/history", methods=["GET"])
@login_required
def history_get(user):
    return jsonify({"history": get_history(user)})


@auth_bp.route("/history", methods=["POST"])
@login_required
def history_post(user):
    entry = request.get_json(silent=True) or {}
    # whitelist fields we store
    clean = {
        "type": str(entry.get("type", "scan"))[:40],
        "label": str(entry.get("label", ""))[:200],
        "verdict": str(entry.get("verdict", ""))[:60],
        "threat": str(entry.get("threat", ""))[:30],
        "detail": str(entry.get("detail", ""))[:300],
    }
    log_history(user, clean)
    return jsonify({"ok": True})


@auth_bp.route("/history", methods=["DELETE"])
@login_required
def history_delete(user):
    clear_history(user)
    return jsonify({"ok": True})
