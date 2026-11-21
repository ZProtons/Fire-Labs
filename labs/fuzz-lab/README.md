# ClearDesk — ffuf Fuzzing Lab

A small internal-tools site with 4 flags, each one mapped to a different
core mode of [ffuf](https://github.com/ffuf/ffuf): path fuzzing, extension
fuzzing, GET-parameter fuzzing, and Host-header (virtual host) fuzzing.

See also: [FUZZING.md](FUZZING.md) — reference notes on the technique.

## Running it

```sh
pip install flask
cd app
python3 app.py
```

Visit `http://127.0.0.1:5006/`.

## Challenge

4 flags. Nothing is linked, nothing is in a comment, nothing is in
robots.txt — this one isn't about reading, it's about brute-forcing. You
need `ffuf` (or an equivalent fuzzer) and a wordlist for each category:

- One hidden directory
- One hidden file, reachable only by guessing its extension
- One hidden GET parameter that changes a page's behavior
- One hidden virtual host, reachable only via the `Host:` header

No further hints. Solutions go to Medium, not this repo.

## How this was built

Built by Claude (Anthropic), on my instructions — every page, every flag
placement. I designed what it needed to cover and solved all 4 flags
myself with real `ffuf` commands before publishing it, to confirm each one
is reachable exactly as intended. Built as the fuzzing companion to
[recon-playbook](https://github.com/ZProtons/recon-playbook) and the SQLi
and XSS labs — recon tells you what's there, fuzzing is how you go find
what isn't supposed to be found.
