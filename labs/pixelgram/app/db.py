import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "pixelgram.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # custom SQL function so time-based blind payloads work the same way
    # a MySQL SLEEP(n) would, since SQLite has no native equivalent.
    conn.create_function("sleep", 1, lambda n: (time.sleep(float(n)), 0)[1])
    return conn


GRADIENTS = [
    "#ec4899, #ef4444, #eab308",
    "#a855f7, #ec4899, #fb923c",
    "#3b82f6, #22d3ee, #5eead4",
    "#4f46e5, #a855f7, #ec4899",
    "#4ade80, #10b981, #0d9488",
    "#fb923c, #fb7185, #d946ef",
]


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            bio TEXT NOT NULL DEFAULT '',
            private_key TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'user',
            avatar_color TEXT NOT NULL DEFAULT '#6366f1'
        )
    """)
    c.execute("""
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            caption TEXT NOT NULL,
            gradient TEXT NOT NULL,
            emoji TEXT NOT NULL,
            likes INTEGER NOT NULL DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE site_secrets (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            value TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            value TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE internal_notes (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            value TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE audit_private (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            ip_note TEXT NOT NULL
        )
    """)

    users = [
        ("alice", "sunshine123", "coffee & code ☕", "", "user", "#f59e0b"),
        ("bob", "footballfan22", "weekend hiker 🏔️", "", "user", "#10b981"),
        ("carol", "iloveplants99", "plant mom 🌿", "", "user", "#ec4899"),
        ("dave_codes", "qwerty2026", "building things that break 🛠️", "", "user", "#3b82f6"),
        ("administrator", "Tr0ub4dor&3_rotated_quarterly", "internal use only", "FLAG{4u7h_byp4ss_1s_st1ll_th3_cl4ss1c}", "admin", "#ef4444"),
    ]
    c.executemany(
        "INSERT INTO users (username, password, bio, private_key, role, avatar_color) VALUES (?,?,?,?,?,?)",
        users,
    )

    posts = [
        (1, "Sunday morning ritual", GRADIENTS[0], "☕"),
        (2, "Trail views don't miss", GRADIENTS[2], "🏔️"),
        (3, "New monstera leaf unfurled today!", GRADIENTS[4], "🍃"),
        (1, "Three cups in and still debugging", GRADIENTS[1], "🐛"),
        (4, "Shipped something today. Small win.", GRADIENTS[3], "🚀"),
        (2, "Golden hour on the ridge", GRADIENTS[5], "🌅"),
    ]
    c.executemany(
        "INSERT INTO posts (user_id, caption, gradient, emoji) VALUES (?,?,?,?)",
        posts,
    )

    comments = [
        (1, 2, "this looks so cozy"),
        (1, 3, "need this energy on a Monday"),
        (2, 1, "wow where is this"),
        (3, 4, "you have a gift honestly"),
        (5, 3, "congrats!! what did you ship"),
    ]
    c.executemany(
        "INSERT INTO comments (post_id, user_id, text) VALUES (?,?,?)",
        comments,
    )

    c.execute(
        "INSERT INTO site_secrets (label, value) VALUES (?,?)",
        ("flag2_union", "FLAG{un10n_s3l3ct_1s_st1ll_th3_l0ud3st_tr1ck}"),
    )
    c.execute(
        "INSERT INTO api_keys (service, value) VALUES (?,?)",
        ("internal_payments_gateway", "FLAG{bl1nd_b00l34n_4v41l4b1l17y_ch3ck}"),
    )
    c.execute(
        "INSERT INTO internal_notes (title, value) VALUES (?,?)",
        ("ops-reminder", "FLAG{t1m1ng_1s_3v3ryth1ng_1n_bl1nd_sql1}"),
    )
    # audit_private deliberately has NO row for a normal username --
    # this table is only ever reachable through the second-order payload.
    c.execute(
        "INSERT INTO audit_private (username, ip_note) VALUES (?,?)",
        ("__flag5_anchor__", "FLAG{st0r3d_t0d4y_d3t0n4t3s_t0m0rr0w}"),
    )

    conn.commit()
    conn.close()
