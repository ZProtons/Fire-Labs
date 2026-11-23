# RequestRelay — SSRF Lab

A four-flag Server-Side Request Forgery lab. Each flag teaches a distinct SSRF
concept, from basic exploitation to filter bypasses.

> Part of [Fire Labs](https://github.com/ZProtons/Fire-Labs) · for authorized
> security research and learning only.

---

## Flags

| Flag | Challenge | Concept |
|------|-----------|---------|
| FLAG 1 | URL Preview (`/fetch`) | Basic SSRF — make the server fetch an internal endpoint |
| FLAG 2 | Avatar Loader (`/avatar`) | Cloud metadata endpoint enumeration |
| FLAG 3 | Webhook Registration (`/webhook/register`) | Blind SSRF — prove it via out-of-band channel |
| FLAG 4 | Export (`/export`) | Filter bypass — circumvent a naive IP blocklist |

No hints in the UI (except FLAG 2 which tells you which port the metadata server
is on — that part's not the challenge). Solutions belong in a Medium write-up,
not a spoiler section here.

---

## Running locally

```bash
pip install flask requests
python app/app.py
# → main app on http://127.0.0.1:5008
# → fake metadata server on http://127.0.0.1:5042
# → blind SSRF callback server on http://127.0.0.1:5043
```

All three servers start automatically.

---

## Reference notes

`SSRF.md` — covers what SSRF is, all major variant types, bypass techniques,
cloud metadata exploitation, using ffuf with SSRF, and defenses. Written
alongside the lab to serve as a standalone reference.

---

## How this was built

Designed and built with Claude (Anthropic) acting as a pair-programmer and
lab architect. The lab design, four-flag structure, filter bypass challenge,
and all reference notes were developed together over one session. All four
flags were verified live before shipping.

The key design decisions:
- Three servers in one process (main app + fake metadata + callback) so setup
  is a single `python app/app.py` with no docker or extra config
- FLAG 4's filter deliberately uses only literal string matching
  (`is_blocked_literal`) to teach the bypass, not to simulate a good defense
- FLAG 3 uses a loopback callback server rather than requiring an external
  listener, keeping the lab fully self-contained
