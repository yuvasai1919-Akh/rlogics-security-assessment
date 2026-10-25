"""INTENTIONALLY VULNERABLE lab application. For local assessment use only.

Run it ONLY bound to localhost (the pipeline publishes it on 127.0.0.1). Never deploy or expose it.

Deliberate weaknesses (each maps to a scanner finding you should be able to explain):
  1. SQL injection via string formatting in /user            -> Semgrep (SAST), ZAP active scan
  2. Unsafe YAML deserialisation (yaml.load) in /import      -> Semgrep
  3. Weak password hashing (MD5)                             -> Semgrep
  4. Flask debug mode enabled                                -> Semgrep
  5. Outdated dependencies with known CVEs (requirements.txt)-> Trivy SCA
  6. Runs as root in the container (Dockerfile)              -> Trivy misconfig
"""
import hashlib
import sqlite3

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, pw TEXT)")
    # (3) weak hash - MD5 is not suitable for password storage
    pw = hashlib.md5(b"lab-password").hexdigest()
    db.executemany(
        "INSERT INTO users (name, email, pw) VALUES (?, ?, ?)",
        [("alice", "alice@example.test", pw), ("bob", "bob@example.test", pw)],
    )
    return db


@app.route("/")
def index():
    return "RLogics lab target (intentionally vulnerable) - do not expose"


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    db = get_db()
    # (1) SQL injection: user input concatenated into the query
    query = "SELECT id, name, email FROM users WHERE name = '%s'" % name
    rows = db.execute(query).fetchall()
    return jsonify(rows)


@app.route("/import", methods=["POST"])
def import_config():
    # (2) unsafe deserialisation: yaml.load without a safe loader
    data = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(received=str(data))


if __name__ == "__main__":
    # (4) debug mode on, listening on all interfaces inside the container
    app.run(host="0.0.0.0", port=8000, debug=True)
