# Vault Bank — Blind Boolean-Based SQLi CTF

A deliberately vulnerable Flask login page built to practice **blind
boolean-based SQL injection** — the harder cousin of the classic
`' OR '1'='1` login bypass. No database errors are ever shown to the
client, and a naive space/keyword filter blocks the obvious payloads, so
you have to find a bypass and script the data extraction blind.

There is no UNION-based path here on purpose — the goal is the blind
technique, not another "see the error, see the data" lab.

## Run it

```sh
cd app
python3 app.py
```

Visit `http://127.0.0.1:5002/`.

## The goal

Extract the flag stored in the `vault_secrets` table, reachable only
through the injectable `username`/`password` fields of `/login`.

## The obstacle

The app rejects any request where `username` or `password` contains:
- a literal space character
- the word `union`
- `select *`
- `--`

This blocks the textbook payloads:
- `' OR '1'='1` (has spaces)
- `' UNION SELECT ...` (has `union` and a space)
- anything relying on a trailing `--` comment

## The technique

Full write-up: [`WRITEUP.md`](WRITEUP.md). Short version: spaces are
replaced with the SQL whitespace-equivalent comment `/**/`, and the
trailing `AND password = '...'` clause is neutralized using operator
precedence (`AND` binds tighter than `OR`) instead of a comment, since
`--` is blocked. From there it's a true/false oracle, extended into a
full data extractor with `exploit.py`.

## Extract it yourself

```sh
pip install requests
python3 exploit.py
```

This recovers the `administrator` password and the flag, character by
character, using nothing but the `Welcome back` / `Invalid username or
password` response difference as a signal.

Use this only against this local lab.
