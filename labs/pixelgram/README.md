# PixelGram

A small social app. Login, sign up, post, search, comment.

```sh
pip install -r requirements.txt
cd app
python3 app.py
```

Visit `http://127.0.0.1:5003/`.

## Challenge

5 flags are hidden somewhere in this app, each in the format `FLAG{...}`.

That's it. No hints, no README spoilers, nothing in the source that points at
itself. Find them the way you'd find them on a real target.

If you finish this one, you've earned the right to say you're actually done
with the fundamentals of SQL injection — not "I followed a tutorial," but
"I broke a real-feeling app with no map." Treat it like a final exam, not
another practice round.

## How this was built

The app was built by Claude (Anthropic), on my instructions, start to
finish — the UI, the backend, every vulnerability, the whole thing. I
designed what it needed to test and exploited every one of the 5 bugs
myself, end to end, before publishing this repo, to confirm the challenge
actually holds up.

What makes this one different from a quick practice lab: it's built to
*look and feel like a real product*, not an obviously-a-lab exercise with
placeholder styling and a vuln list taped to the README. That's deliberate
— the more a target looks like something real, the more it actually tests
whether you can find a bug without being told where to look, which is the
whole point of a black-box challenge like this.
