import hmac
import os
import sqlite3
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, g, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-production")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
)

DB_PATH = os.environ.get("DB_PATH", "devices.db")
MAX_ATTEMPTS = 3
ph = PasswordHasher()  # Argon2id

# ---------- Fixed login from Render Environment Variables ----------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError("Set ADMIN_USERNAME and ADMIN_PASSWORD environment variables.")

# Password is hashed with Argon2id in memory; plain password is never compared directly.
ADMIN_HASH = ph.hash(ADMIN_PASSWORD)


# ---------- Database (device block only) ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            is_blocked INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    db.commit()
    db.close()


init_db()


# ---------- Device tracking (block the phone, not the account) ----------
@app.before_request
def identify_device():
    device_id = request.cookies.get("device_id")
    g.set_cookie = False
    if not device_id:
        device_id = str(uuid.uuid4())
        g.set_cookie = True
    g.device_id = device_id
    db = get_db()
    db.execute("INSERT OR IGNORE INTO devices (device_id) VALUES (?)", (device_id,))
    db.commit()


@app.after_request
def attach_device_cookie(resp):
    if getattr(g, "set_cookie", False):
        resp.set_cookie(
            "device_id",
            g.device_id,
            max_age=60 * 60 * 24 * 365 * 10,
            httponly=True,
            samesite="Lax",
            secure=app.config["SESSION_COOKIE_SECURE"],
        )
    return resp


def get_device():
    return get_db().execute(
        "SELECT * FROM devices WHERE device_id = ?", (g.device_id,)
    ).fetchone()


# ---------- Routes ----------
@app.route("/")
def home():
    return redirect(url_for("welcome" if "user" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    device = get_device()
    if device["is_blocked"]:
        return render_template("login.html", blocked=True), 403

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user_ok = hmac.compare_digest(username.encode(), ADMIN_USERNAME.encode())
        try:
            ph.verify(ADMIN_HASH, password)
            pass_ok = True
        except VerifyMismatchError:
            pass_ok = False

        db = get_db()
        if user_ok and pass_ok:
            db.execute(
                "UPDATE devices SET failed_attempts = 0 WHERE device_id = ?",
                (g.device_id,),
            )
            db.commit()
            session["user"] = ADMIN_USERNAME
            return redirect(url_for("welcome"))

        attempts = device["failed_attempts"] + 1
        blocked = 1 if attempts >= MAX_ATTEMPTS else 0
        db.execute(
            "UPDATE devices SET failed_attempts = ?, is_blocked = ? WHERE device_id = ?",
            (attempts, blocked, g.device_id),
        )
        db.commit()
        if blocked:
            return render_template("login.html", blocked=True), 403
        error = f"Wrong username or password. {MAX_ATTEMPTS - attempts} attempt(s) left."

    return render_template("login.html", error=error, blocked=False)


@app.route("/welcome")
def welcome():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("welcome.html", user=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
