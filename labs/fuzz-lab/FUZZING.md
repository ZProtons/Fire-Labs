# Web Fuzzing with ffuf — Notes

Companion to [recon-playbook](https://github.com/ZProtons/recon-playbook),
[sqli-notes](https://github.com/ZProtons/sqli-notes), and
[XSS.md](https://github.com/ZProtons/Fire-Labs/blob/main/labs/xss-lab/XSS.md).
Fuzzing sits between the two: it's active, automated, and it's how you turn
a wordlist into actual discovered attack surface.

## Table of contents

1. [What fuzzing is](#1-what-fuzzing-is)
2. [The FUZZ keyword](#2-the-fuzz-keyword)
3. [The four things you fuzz](#3-the-four-things-you-fuzz)
4. [Filtering: the part that actually matters](#4-filtering-the-part-that-actually-matters)
5. [Recursion](#5-recursion)
6. [Wordlists](#6-wordlists)
7. [Being a reasonable citizen](#7-being-a-reasonable-citizen)
8. [Cheat sheet](#8-cheat-sheet)

---

## 1. What fuzzing is

Throwing a large list of candidate values at an input and watching what
comes back different. Not guessing one thing — trying thousands, fast, and
using the *shape* of each response (status code, size, word count, line
count, timing) to tell signal from noise. ffuf is the tool; the wordlist is
the question; the response differences are the answer.

## 2. The FUZZ keyword

Everything in ffuf revolves around literally putting the word `FUZZ`
wherever the payload should go — in the URL, in a header, in POST data —
and ffuf substitutes each wordlist line in:

```sh
ffuf -w wordlist.txt -u https://target.test/FUZZ
```

That one keyword is why the same tool fuzzes paths, extensions, parameter
names, header values, and POST bodies — it's just a question of *where*
you put `FUZZ`.

## 3. The four things you fuzz

**Directories/paths** — the obvious one. Unlinked admin panels, staging
endpoints, old API versions:

```sh
ffuf -w common.txt -u https://target.test/FUZZ
```

**Extensions** — a path can exist under a name you already guessed, just
not the extension you assumed. Backup files, old configs, editor swap
files:

```sh
ffuf -w extensions.txt -u https://target.test/settings.FUZZ
# or, combined with a path wordlist using ffuf's -e flag:
ffuf -w paths.txt -u https://target.test/FUZZ -e .bak,.old,.zip,.swp
```

**Parameter names** — the page looks finished, but an undocumented query
param flips on a debug view, a preview mode, or an internal flag nobody
meant to ship live:

```sh
ffuf -w param-names.txt -u "https://target.test/page?FUZZ=1"
```

**Host headers (virtual hosts)** — a server can host more than one
application distinguished only by the `Host:` header, with no DNS record
pointing anyone there:

```sh
ffuf -w subdomains.txt -u https://target.test/ -H "Host: FUZZ.target.test"
```

Same tool, same keyword, four completely different categories of hidden
surface.

## 4. Filtering: the part that actually matters

A wordlist of 10,000 entries against a real app will return a dozen false
leads for every genuine hit, unless you filter the noise before you look.
ffuf gives you both directions:

- `-mc` (match code) — e.g. `-mc 200,301,403` to only show interesting
  statuses. The opposite of what beginners expect: a 403 is often *more*
  interesting than a 200, because it means something exists and is being
  actively blocked.
- `-fc` / `-fs` / `-fw` / `-fl` (filter code/size/words/lines) — hide
  responses matching a known "nothing here" shape. This is the one that
  actually matters in practice: most apps return the same custom 200-status
  "not found" page for every miss, so filtering by *size* (`-fs <bytes>`)
  or *word count* (`-fw <n>`) of that known-bad response is what separates
  real hits from static noise — status code alone won't save you.

The workflow that works every time: make one request to something you know
doesn't exist, note its size/word count, then filter that exact shape out
before fuzzing for real.

## 5. Recursion

`-recursion -recursion-depth 2` tells ffuf to re-run itself inside every
directory it finds, automatically. Useful, but it multiplies request count
fast — combine it with a tight `-mc`/`-fs` filter or it turns into noise
multiplied by noise.

## 6. Wordlists

[SecLists](https://github.com/danielmiessler/SecLists) is the default
answer for all four categories:
`Discovery/Web-Content/common.txt` (paths),
`Discovery/Web-Content/raft-small-words.txt` (parameter names),
`Discovery/DNS/subdomains-top1million-*.txt` (vhosts). A short,
hand-written wordlist targeted at what the specific app *looks like* it
might contain often beats a generic 50,000-line list — context beats
volume.

## 7. Being a reasonable citizen

`-rate <n>` caps requests per second; `-t <n>` caps concurrent threads.
Fuzzing an app with no rate limit at full ffuf speed can look identical to
a denial-of-service attempt from the other side, authorized or not. Start
slow, especially against anything you don't own outright.

## 8. Cheat sheet

```sh
# Baseline a known-miss response first
curl -s https://target.test/definitely-not-a-real-path | wc -c

# Directories, filtering out that known size
ffuf -w common.txt -u https://target.test/FUZZ -fs 1234

# Extensions on a known filename
ffuf -w extensions.txt -u https://target.test/config.FUZZ -mc 200

# GET parameter name
ffuf -w params.txt -u "https://target.test/page?FUZZ=1" -fs 1234

# POST parameter name
ffuf -w params.txt -u https://target.test/page -X POST -d "FUZZ=1" -H "Content-Type: application/x-www-form-urlencoded" -fs 1234

# Virtual hosts via Host header
ffuf -w subdomains.txt -u https://target.test/ -H "Host: FUZZ.target.test" -fs 1234

# Recursive, rate-limited, quiet
ffuf -w common.txt -u https://target.test/FUZZ -recursion -recursion-depth 2 -rate 20 -mc 200,301,403 -s
```

Related: [recon-playbook](https://github.com/ZProtons/recon-playbook) ·
[sqli-notes](https://github.com/ZProtons/sqli-notes)
