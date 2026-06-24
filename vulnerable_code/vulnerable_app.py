"""
SecureNotes - A note-taking web application
"Enterprise-grade" note management platform
"""

import os
import sqlite3
import pickle
import hashlib
import subprocess
import base64
import urllib.request
from flask import (Flask, request, session, redirect, render_template_string,
                   jsonify, send_file, make_response)

app = Flask(__name__)
app.secret_key = "supersecretkey123"
app.config['DEBUG'] = True

DATABASE = "/tmp/securenotes.db"

ADMIN_API_KEY = "sk_live_abcdef123456789"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            api_key TEXT
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            is_private INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    password_hash = hashlib.md5("admin123".encode()).hexdigest()
    db.execute(
        "INSERT OR IGNORE INTO users (username, password, role, api_key) VALUES (?, ?, ?, ?)",
        ("admin", password_hash, "admin", ADMIN_API_KEY)
    )
    db.commit()


HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>SecureNotes</title></head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <h2>Your Notes</h2>
    {% for note in notes %}
    <div class="note">
        <h3>{{ note['title'] | safe }}</h3>
        <p>{{ note['content'] | safe }}</p>
    </div>
    {% endfor %}
    <h2>Create Note</h2>
    <form method="POST" action="/note/create">
        <input name="title" placeholder="Title"><br>
        <textarea name="content" placeholder="Content"></textarea><br>
        <button type="submit">Save</button>
    </form>
    <br>
    <a href="/search">Search Notes</a> |
    <a href="/profile">Profile</a> |
    <a href="/logout">Logout</a>
</body>
</html>
"""

SEARCH_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Search - SecureNotes</title></head>
<body>
    <h1>Search Notes</h1>
    <form method="GET" action="/search">
        <input name="q" value="{{ query }}">
        <button type="submit">Search</button>
    </form>
    <p>Showing results for: """ + "{{ query | safe }}" + """</p>
    {% for note in results %}
    <div>
        <h3>{{ note['title'] }}</h3>
        <p>{{ note['content'] }}</p>
    </div>
    {% endfor %}
    <a href="/">Back</a>
</body>
</html>
"""


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    notes = db.execute("SELECT * FROM notes WHERE user_id = ?", (session["user_id"],)).fetchall()
    return render_template_string(HOME_TEMPLATE, username=user["username"], notes=notes)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = hashlib.md5(password.encode()).hexdigest()

        db = get_db()
        db.execute(
            "INSERT INTO users (username, password, role) VALUES ('" +
            username + "', '" + password_hash + "', 'user')"
        )
        db.commit()
        return redirect("/login")

    return render_template_string("""
        <h1>Register</h1>
        <form method="POST">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Register</button>
        </form>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = hashlib.md5(password.encode()).hexdigest()

        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        user = db.execute(query).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            resp = make_response(redirect("/"))
            resp.set_cookie("user_role", user["role"])
            return resp
        return "Invalid credentials", 401

    return render_template_string("""
        <h1>Login</h1>
        <form method="POST">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
        <a href="/register">Register</a>
    """)


@app.route("/note/create", methods=["POST"])
def create_note():
    if "user_id" not in session:
        return redirect("/login")

    title = request.form["title"]
    content = request.form["content"]

    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (session["user_id"], title, content)
    )
    db.commit()
    return redirect("/")


@app.route("/note/<int:note_id>")
def view_note(note_id):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        return "Not found", 404
    return render_template_string("""
        <h2>{{ note['title'] | safe }}</h2>
        <p>{{ note['content'] | safe }}</p>
    """, note=note)


@app.route("/note/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id):
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return redirect("/")


@app.route("/search")
def search():
    query = request.args.get("q", "")
    db = get_db()
    results = db.execute(
        "SELECT * FROM notes WHERE title LIKE '%" + query + "%' OR content LIKE '%" + query + "%'"
    ).fetchall()
    return render_template_string(SEARCH_TEMPLATE, query=query, results=results)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    if request.method == "POST":
        new_role = request.form.get("role", "user")
        db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, session["user_id"]))
        db.commit()

    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template_string("""
        <h1>Profile: {{ user['username'] }}</h1>
        <p>Role: {{ user['role'] }}</p>
        <p>API Key: {{ user['api_key'] }}</p>
        <form method="POST">
            <input name="display_name" placeholder="Display Name"><br>
            <button type="submit">Update</button>
        </form>
    """, user=user)


@app.route("/export")
def export_notes():
    if "user_id" not in session:
        return redirect("/login")

    fmt = request.args.get("format", "txt")
    filename = request.args.get("filename", "notes")
    filepath = f"/tmp/exports/{filename}.{fmt}"

    db = get_db()
    notes = db.execute("SELECT * FROM notes WHERE user_id = ?", (session["user_id"],)).fetchall()

    os.makedirs("/tmp/exports", exist_ok=True)
    with open(filepath, "w") as f:
        for note in notes:
            f.write(f"{note['title']}: {note['content']}\n")

    return send_file(filepath, as_attachment=True)


@app.route("/import", methods=["POST"])
def import_notes():
    if "user_id" not in session:
        return redirect("/login")

    data = request.form.get("data", "")
    decoded = base64.b64decode(data)
    notes = pickle.loads(decoded)

    db = get_db()
    for note in notes:
        db.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (session["user_id"], note["title"], note["content"])
        )
    db.commit()
    return redirect("/")


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if url:
        response = urllib.request.urlopen(url)
        return response.read()
    return "Provide a URL", 400


@app.route("/admin/run", methods=["POST"])
def admin_run():
    if request.cookies.get("user_role") != "admin":
        return "Forbidden", 403

    cmd = request.form.get("command", "")
    result = subprocess.check_output(cmd, shell=True)
    return result


@app.route("/api/notes")
def api_notes():
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        return jsonify({"error": "API key required"}), 401

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE api_key = ?", (api_key,)).fetchone()
    if not user:
        return jsonify({"error": "Invalid API key"}), 403

    notes = db.execute("SELECT * FROM notes").fetchall()
    return jsonify([dict(n) for n in notes])


@app.route("/download")
def download():
    filepath = request.args.get("file", "")
    return send_file(filepath)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/debug/users")
def debug_users():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return jsonify([dict(u) for u in users])


@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True)
    callback_url = data.get("callback_url", "")
    if callback_url:
        urllib.request.urlopen(callback_url)
    return "OK"


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
