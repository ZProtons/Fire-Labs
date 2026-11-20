# FeedbackLoop — XSS Lab

A small, deliberately vulnerable product-feedback site covering all three
XSS categories: reflected, stored, and DOM-based.

See also: [XSS.md](XSS.md) — reference notes on the technique itself.

## Running it

```sh
pip install flask
cd app
python3 app.py
```

Visit `http://127.0.0.1:5005/`.

## Challenge

3 flags, one per XSS category (reflected, stored, DOM-based). Each flag is
stored in its own non-httpOnly cookie — you can only read it by actually
getting your JavaScript to execute in the page, not by viewing source.

One endpoint filters a couple of obvious patterns. That's intentional.

No further hints. Solutions go to Medium, not this repo.

## How this was built

Built by Claude (Anthropic), on my instructions — every page, every flag
placement, every filter. I designed what it needed to cover and verified
all 3 flags myself, end to end, before publishing it. Built as the
practical companion to [sqli-notes](https://github.com/ZProtons/sqli-notes)
— SQLi and XSS are the two web-vuln categories every pentest fundamentals
checklist expects, and this was the gap.
