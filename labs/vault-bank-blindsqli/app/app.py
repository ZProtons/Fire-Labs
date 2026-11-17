from flask import Flask, request, render_template, make_response
import sqlite3
import db

app = Flask(__name__)

BLOCKED_SUBSTRINGS = [" ", "union", "select *", "--"]


def is_blocked(value: str) -> bool:
    lowered = value.lower()
    return any(bad in lowered for bad in BLOCKED_SUBSTRINGS)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", message=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # naive keyword/character filter -- the first obstacle.
    # blocks the literal space character, the word "union", "select *", and "--"
    if is_blocked(username) or is_blocked(password):
        return render_template(
            "login.html",
            message="Invalid characters detected in request.",
        ), 400

    conn = db.get_conn()
    cur = conn.cursor()

    # VULNERABLE: string-built query, no parameterization.
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
        # deliberately indistinguishable from a normal failed login --
        # no verbose DB errors are ever shown to the client.
        row = None
    finally:
        conn.close()

    if row:
        return render_template("login.html", message=f"Welcome back, {row['username']}!")
    else:
        return render_template("login.html", message="Invalid username or password.")


if __name__ == "__main__":
    import os

    if not os.path.exists(db.DB_PATH):
        db.init_db()
    app.run(host="0.0.0.0", port=5002, debug=True)
