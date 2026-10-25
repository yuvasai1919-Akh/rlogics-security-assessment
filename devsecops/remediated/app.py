"""Remediated version of the lab application. See ../FINDINGS_BEFORE_AFTER.md for the diff rationale."""
import os
import sqlite3

import yaml
from flask import Flask, abort, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
MAX_BODY = 64 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY  # bound request size (unbounded input is a DoS risk)


def get_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, pw TEXT)")
    # (3) fixed: salted, slow hash instead of MD5
    pw = generate_password_hash("lab-password")
    db.executemany(
        "INSERT INTO users (name, email, pw) VALUES (?, ?, ?)",
        [("alice", "alice@example.test", pw), ("bob", "bob@example.test", pw)],
    )
    return db


@app.after_request
def security_headers(resp):
    # Addresses typical ZAP baseline warnings
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.route("/")
def index():
    return "RLogics lab target (remediated)"


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    if len(name) > 64:
        abort(400)
    db = get_db()
    # (1) fixed: parameterised query - input is data, never SQL
    rows = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()
    return jsonify(rows)


@app.route("/import", methods=["POST"])
def import_config():
    # (2) fixed: safe_load only constructs plain data types
    try:
        data = yaml.safe_load(request.data)
    except yaml.YAMLError:
        abort(400)
    return jsonify(received=str(data))


if __name__ == "__main__":
    # (4) fixed: debug is never enabled in code; production runs under gunicorn (see Dockerfile)
    app.run(host="127.0.0.1", port=8000, debug=os.environ.get("FLASK_DEBUG") == "1" and False)
