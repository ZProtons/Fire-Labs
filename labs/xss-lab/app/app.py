from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

FLAG1 = "FLAG{r3fl3ct3d_but_st1ll_d4ng3r0us}"
FLAG2 = "FLAG{p3rs1st3nc3_1s_th3_p01nt}"
FLAG3 = "FLAG{th3_s3rv3r_n3v3r_s4w_1t}"

# Feedback wall storage (stored XSS target) — in-memory, resets on restart.
FEEDBACK = [
    {"name": "Priya", "message": "Great product, shipped fast!"},
    {"name": "Marcus", "message": "Customer support was really helpful."},
]

BLOCKED_TOKENS = ["<script", "javascript:"]


def is_blocked(raw: str) -> bool:
    lowered = raw.lower()
    return any(tok in lowered for tok in BLOCKED_TOKENS)


@app.after_request
def set_flag_cookies(resp):
    # Flags live in cookies that are NOT httpOnly — readable only via JS
    # execution in the victim's browser, i.e. only if your payload runs.
    resp.set_cookie("ctf_flag1", FLAG1, httponly=False, samesite="Lax")
    resp.set_cookie("ctf_flag2", FLAG2, httponly=False, samesite="Lax")
    resp.set_cookie("ctf_flag3", FLAG3, httponly=False, samesite="Lax")
    return resp


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    blocked = False
    if q and is_blocked(q):
        blocked = True
        q = ""
    # Reflected: rendered back into the page without escaping.
    return render_template("search.html", query=q, blocked=blocked)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "Anonymous").strip() or "Anonymous"
        message = request.form.get("message", "")
        if message:
            FEEDBACK.append({"name": name, "message": message})
        return redirect(url_for("feedback"))
    # Stored: every past message is rendered without escaping.
    return render_template("feedback.html", entries=FEEDBACK)


@app.route("/welcome")
def welcome():
    # DOM-based: the page's own JS reads location.hash client-side and
    # writes it into the DOM with innerHTML. Nothing here ever touches
    # the server — the payload lives entirely in the URL fragment.
    return render_template("welcome.html")


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=True)
