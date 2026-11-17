from flask import Flask, request, render_template, redirect, session, jsonify, url_for
import sqlite3
import os
import db

app = Flask(__name__)
app.secret_key = os.urandom(24)


def current_user():
    if "user_id" not in session:
        return None
    conn = db.get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()
    return row


def require_login():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return None


@app.route("/")
def feed():
    redir = require_login()
    if redir:
        return redir
    conn = db.get_conn()
    posts = conn.execute("""
        SELECT posts.*, users.username, users.avatar_color
        FROM posts JOIN users ON posts.user_id = users.id
        ORDER BY posts.id DESC
    """).fetchall()
    conn.close()
    return render_template("feed.html", posts=posts, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = db.get_conn()
    cur = conn.cursor()

    # VULNERABLE: string-built auth query.
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )

    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()

    if row:
        session["user_id"] = row["id"]
        session["role"] = row["role"]
        return redirect(url_for("feed"))
    return render_template("login.html", error="Incorrect username or password.")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html", error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    bio = request.form.get("bio", "")[:140]

    if not username or not password:
        return render_template("signup.html", error="Username and password required.")

    conn = db.get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password, bio, avatar_color) VALUES (?,?,?,?)",
            (username, password, bio, "#8b5cf6"),
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return render_template("signup.html", error="That username is already taken.")
    conn.close()

    session["user_id"] = new_id
    session["role"] = "user"
    return redirect(url_for("feed"))


@app.route("/api/check-username")
def check_username():
    """
    Used by the signup page's live-availability indicator.
    VULNERABLE: string-built query, boolean result reflected directly.
    """
    username = request.args.get("username", "")
    conn = db.get_conn()
    cur = conn.cursor()

    query = "SELECT COUNT(*) as c FROM users WHERE username = '" + username + "'"

    try:
        cur.execute(query)
        row = cur.fetchone()
        available = (row["c"] == 0)
    except sqlite3.Error:
        available = False
    finally:
        conn.close()

    return jsonify({"available": available})


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html", submitted=False)

    identifier = request.form.get("username", "")

    conn = db.get_conn()
    cur = conn.cursor()

    # VULNERABLE: string-built query. The response text is IDENTICAL
    # whether this matches a user or not, by design -- no content-based
    # oracle here on purpose.
    query = "SELECT * FROM users WHERE username = '" + identifier + "'"

    try:
        cur.execute(query)
        cur.fetchone()
    except sqlite3.Error:
        pass
    finally:
        conn.close()

    # always the same message, regardless of what happened above
    return render_template("forgot_password.html", submitted=True)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        conn = db.get_conn()
        cur = conn.cursor()

        # VULNERABLE: string-built UNION query across posts and users.
        query = (
            "SELECT posts.id, posts.caption, 'post' as kind FROM posts "
            "WHERE posts.caption LIKE '%" + q + "%' "
            "UNION "
            "SELECT users.id, users.username, 'user' as kind FROM users "
            "WHERE users.username LIKE '%" + q + "%'"
        )
        try:
            cur.execute(query)
            results = cur.fetchall()
        except sqlite3.Error:
            results = []
        finally:
            conn.close()

    return render_template("search.html", q=q, results=results, user=current_user())


@app.route("/u/<username>")
def profile(username):
    redir = require_login()
    if redir:
        return redir
    conn = db.get_conn()
    profile_user = conn.execute(
        "SELECT id, username, bio, avatar_color, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    posts = []
    if profile_user:
        posts = conn.execute(
            "SELECT * FROM posts WHERE user_id = ? ORDER BY id DESC",
            (profile_user["id"],),
        ).fetchall()
    conn.close()
    if not profile_user:
        return render_template("profile.html", profile_user=None, posts=[], user=current_user())
    return render_template("profile.html", profile_user=profile_user, posts=posts, user=current_user())


@app.route("/account")
def account():
    redir = require_login()
    if redir:
        return redir
    return render_template("account.html", user=current_user())


@app.route("/post/<int:post_id>")
def post_detail(post_id):
    redir = require_login()
    if redir:
        return redir
    conn = db.get_conn()
    post = conn.execute("""
        SELECT posts.*, users.username, users.avatar_color
        FROM posts JOIN users ON posts.user_id = users.id
        WHERE posts.id = ?
    """, (post_id,)).fetchone()
    comments = conn.execute("""
        SELECT comments.*, users.username, users.avatar_color
        FROM comments JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
        ORDER BY comments.id ASC
    """, (post_id,)).fetchall()
    conn.close()
    return render_template("post.html", post=post, comments=comments, user=current_user())


@app.route("/admin/audit")
def admin_audit():
    redir = require_login()
    if redir:
        return redir
    if session.get("role") != "admin":
        return "Forbidden", 403

    conn = db.get_conn()
    cur = conn.cursor()
    usernames = [r["username"] for r in conn.execute("SELECT username FROM users ORDER BY id DESC LIMIT 10")]

    rows = []
    for uname in usernames:
        # VULNERABLE: each stored username is concatenated, unescaped,
        # into a second query here -- long after it was first accepted
        # (and validated-looking) at signup. Classic second-order SQLi.
        query = "SELECT ip_note FROM audit_private WHERE username = '" + uname + "'"
        try:
            cur.execute(query)
            r = cur.fetchone()
            note = r["ip_note"] if r else "no record"
        except sqlite3.Error as e:
            note = f"lookup error"
        rows.append({"username": uname, "note": note})
    conn.close()

    return render_template("admin_audit.html", rows=rows, user=current_user())


if __name__ == "__main__":
    if not os.path.exists(db.DB_PATH):
        db.init_db()
    app.run(host="0.0.0.0", port=5003, debug=False)
