from flask import Flask, request, render_template, abort

app = Flask(__name__)

FLAG1 = "FLAG{d1rs_h1dd3n_fr0m_l1nks_n0t_fr0m_w0rdl1sts}"
FLAG2 = "FLAG{3xt3ns10ns_ar3_j5t_an0th3r_w0rdl1st}"
FLAG3 = "FLAG{param3t3r_nam35_ar3_atta ck_surfac3}".replace(" ", "")
FLAG4 = "FLAG{v1rtu4l_h0sts_h1d3_wh0l3_4pp5}"

# Note on FLAG3: constructed oddly on purpose so grep for the literal
# string in this source doesn't trivially leak it if someone skims.


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/dashboard")
def dashboard():
    # Undocumented GET param that unlocks an internal view.
    # Nothing links to this, nothing mentions its name anywhere in the
    # rendered HTML -- it only exists in the route's own logic.
    if request.args.get("preview") == "true":
        return render_template("dashboard_preview.html", flag=FLAG3)
    return render_template("dashboard.html")


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# --- Hidden directory (not linked from anywhere, no robots.txt hint) ---
@app.route("/staging-ops/")
def staging_ops():
    return render_template("staging_ops.html", flag=FLAG1)


# --- Hidden file via extension fuzzing: /settings exists, but only as
# a backup file with an unexpected extension. ---
@app.route("/settings.bak")
def settings_bak():
    return (
        "# ClearDesk settings backup -- do not deploy with this file present\n"
        "admin_email=ops@cleardesk.example\n"
        "debug_mode=false\n"
        f"recovery_note={FLAG2}\n",
        200,
        {"Content-Type": "text/plain"},
    )


@app.before_request
def vhost_routing():
    # Virtual-host fuzzing target: a Host header of
    # internal.cleardesk.local serves a completely different (and
    # otherwise unreachable) internal page, on any path, short-circuiting
    # every other route. Nothing in the normal site links to this host.
    host = request.host.split(":")[0]
    if host == "internal.cleardesk.local":
        return render_template("internal_portal.html", flag=FLAG4)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5006, debug=True)
