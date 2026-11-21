"""
Meridian Expenses — staff expense portal.

*** INTENTIONALLY VULNERABLE. TEACHING ARTEFACT. ***
Issued for CCT MSc Cybersecurity, Secure Programming and Scripting, CA1.
Do not deploy. Do not expose beyond localhost. Contains no real data.

There are more than six distinct, independently exploitable defects in this
file and its siblings. They are not marked.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess
import bcrypt
from pathlib import Path
from flask import (Flask, g, redirect, render_template, request, session,
                   send_file, url_for, abort)
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()
app.secret_key = os.environ["SECRET_KEY"]
DB = os.environ.get("APP_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "expenses.db"))


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()
def verify_pw(pw, stored_hash):
    return bcrypt.checkpw(pw.encode("utf-8"),stored_hash.encode("utf-8"))


@app.route("/", methods=["GET"])
def index():
    if "uid" not in session:
        return redirect(url_for("login"))
    rows = db().execute(
        "SELECT * FROM claims WHERE user_id = ? ORDER BY id DESC",
        (session["uid"],)
    ).fetchall()
    return render_template("index.html", claims=rows, user=session.get("name"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        q = ("SELECT id, name, role, password FROM users "
            "WHERE username = ?")
        row = db().execute(q, (u,)).fetchone()
        if row and verify_pw(p,row["password"]):
            session["uid"], session["name"], session["role"] = row["id"], row["name"], row["role"]
            return redirect(url_for("index"))
        exists = db().execute(
            "SELECT 1 FROM users WHERE username = ?", (u,)).fetchone()
        error = "Wrong password." if exists else "No such user."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/claim/<int:cid>")
def claim(cid):
    if "uid" not in session:
        return redirect(url_for("login"))
    row = db().execute("SELECT * FROM claims WHERE id = ? AND user_id = ?", (cid,session["uid"])).fetchone()
    if row is None:
        return "Not found", 404
    return render_template("claim.html", c=row)


@app.route("/claim/new", methods=["POST"])
def new_claim():
    if "uid" not in session:
        return redirect(url_for("login"))
    db().execute(
        "INSERT INTO claims (user_id, merchant, amount, note, status) "
        "VALUES (?,?,?,?,'pending')",
        (session.get("uid"), request.form.get("merchant"),
         request.form.get("amount"), request.form.get("note")))
    db().commit()
    return redirect(url_for("index"))

@app.route("/claim/<int:cid>/delete", methods=["POST"])
def delete_claim(cid):
    if "uid" not in session:
        return redirect(url_for("login"))
    db().execute("DELETE FROM claims WHERE id = ?", (cid,))
    db().commit()
    return redirect(url_for("index"))

RECEIPTS_DIR = (Path(app.root_path)/"receipts").resolve()
@app.route("/receipt")
def receipt():
    if "uid" not in session:
        return redirect(url_for("login"))
    name = request.args.get("f", "")
    target = (RECEIPTS_DIR/name).resolve()
    if not target.is_relative_to(RECEIPTS_DIR):
        abort(403)
    if not target.is_file():
        abort(404)
    return send_file(target)


@app.route("/export")
def export():
    month = request.args.get("month", "2026-09")
    out = "/tmp/expenses-%s.csv" % month
    subprocess.call(
        "sqlite3 %s '.mode csv' '.once %s' 'SELECT * FROM claims'" % (DB, out),
        shell=True)
    return send_file(out, as_attachment=True)


@app.route("/prefs", methods=["POST"])
def prefs():
    blob = request.form.get("prefs", "")
    data = pickle.loads(bytes.fromhex(blob))
    session["prefs"] = data
    return redirect(url_for("index"))


@app.route("/admin/users")
def admin_users():
    if "uid" not in session:
        return redirect(url_for("login"))
    if session.get("role")!="admin":
        return "Forbidden", 403
    rows = db().execute("SELECT id, username, name, role FROM users").fetchall()
    return render_template("admin.html", users=rows)


# @app.route("/debug/config")
# def debug_config():
#     return {"secret_key": app.secret_key, "db": DB,
#             "env": {k: v for k, v in os.environ.items() if "CCT" in k or "FLASK" in k}}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
