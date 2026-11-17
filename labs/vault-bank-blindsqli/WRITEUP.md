# Blind Boolean-Based SQL Injection: Extracting a Flag Through a Login Form That Never Says a Word

Most people's first SQL injection is `' OR '1'='1'--`. It's satisfying
because the app tells you exactly what happened — a login succeeds, a
database error appears, a page suddenly shows every row in a table.
Blind injection takes that feedback away. The app answers in exactly
two ways no matter what you throw at it: "Welcome back" or "Invalid
username or password." Nothing else. No stack trace, no error message,
no extra row of data. If there's a vulnerability here at all, you have
to prove it using only that single bit of signal, over and over, until
it adds up to a password and a flag.

This is a walkthrough of doing exactly that against a small lab I built
called Vault Bank — a bank-style login form with one field for username,
one for password, and a SQL injection buried in a string-concatenated
query. The challenge wasn't finding the bug. It was getting anything
useful out of it once a filter started rejecting my first three
attempts.

## Finding the shape of the problem

The login endpoint takes `username` and `password` and runs this query
under the hood:

```python
query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "' AND password = '"
    + password
    + "'"
)
```

No parameterization, no escaping. Classic injection point. My first
instinct was the oldest trick in the book:

```
username = admin' OR '1'='1
```

Rejected: *"Invalid characters detected in request."* Not a SQL error —
a filter, catching the request before it ever touches the database.

## Working out what's actually blocked

A filter that rejects a payload outright is more useful than it looks,
because the error message tells you it *saw* something it didn't like,
without telling you what. So I probed it piece by piece instead of
guessing the whole payload at once:

- `admin'` alone → accepted (just fails the login normally)
- `admin' OR` → rejected
- `admin'OR` (no space) → still rejected — so it's not just blocking
  the keyword next to a space, it's scanning for the substring `or`...
  except `administrator` itself logs in fine elsewhere, so it's not
  blocking the raw letters `o`-`r`. It's blocking the **literal space
  character** itself, anywhere in the field.
- Any payload with `--` in it → rejected
- Any payload with `union` or `select *` → rejected

So the filter isn't smart. It's a blocklist on exact substrings: a
space, `union`, `select *`, `--`. That's actually four separate holes,
not one.

## Bypassing the space filter

SQL doesn't require literal spaces — a comment acts as whitespace to the
parser as long as it doesn't change meaning. SQLite (and most other
engines) treat `/**/` exactly like a space:

```
SELECT/**/*/**/FROM/**/users
```

parses identically to a normal query with real spaces, but contains no
space character for the filter to catch. That handles obstacle #1.

## Losing my favorite tool: the trailing comment

Every blind SQLi payload I'd ever used ended in `--` to comment out
whatever the original query expected after my injection point. That's
exactly what's blocked here. Without it, my injected content has to
coexist with the rest of the original query — `' AND password = '<p>'`
— instead of erasing it.

This is where operator precedence saved the payload. In SQL, `AND`
binds more tightly than `OR`. So if I inject into `username` as:

```
nonexistent' OR (<SOMETHING>) OR 'x'='y
```

the full WHERE clause becomes:

```sql
username = 'nonexistent' OR (<SOMETHING>) OR 'x'='y' AND password = '<whatever>'
```

which the parser groups as:

```
(username = 'nonexistent') OR (<SOMETHING>) OR ('x'='y' AND password = '<whatever>')
```

`'x'='y'` is always false, so that last clause is always false — no
matter what password I send. The real `password` check is neutralized
without ever touching a comment. The row is returned (or not) purely
based on whether `<SOMETHING>` is true. I'd accidentally built a working
oracle.

## Turning a yes/no into a password

With the comment problem solved, I had a working boolean oracle:
put any true/false SQL expression where `<SOMETHING>` goes, and the
"Welcome back" vs "Invalid" response tells me which one it was.

First test, to prove it:

```
<SOMETHING> = (SELECT substr(password,1,1) FROM users WHERE username='administrator')='n'
```

→ **"Welcome back, alice!"** True. (It returns alice because the
condition becomes true for every row, and the app just grabs the first
match — a reminder that in a blind context, *who* the response claims
to be doesn't matter, only *whether* it succeeded.)

Change the guessed letter to `'z'` → **"Invalid username or password."**
False. The oracle works.

From here it's mechanical: instead of guessing one character at a time,
binary-search the ASCII range for each character position using
`unicode(substr(...))<=N`, and first binary-search the overall string
length with `length(...)=N`. That turns an alphabet-sized guess per
character into about 7 requests per character (log2 of ~95 printable
characters), which is the difference between a lab you can actually
finish and one that times out your patience first.

## Automating it

```python
def oracle(boolean_expr):
    payload = f"nonexistent'/**/OR/**/({boolean_expr})/**/OR/**/'x'='y"
    payload = payload.replace(" ", "/**/")  # catches spaces inside boolean_expr too
    r = requests.post(URL, data={"username": payload, "password": "whatever"})
    return "Welcome back" in r.text
```

Wrapped in a length-then-binary-search loop, this pulled the
`administrator` password and the flag out character by character, with
zero database errors shown and zero direct data returned by the server
— just a long sequence of true/false answers.

**Extracted:**
- `administrator` password: `n0t_th3_fl4g_7h1s_1s_j7st_th3_p4ssw0rd`
- Flag: `FLAG{bl1nd_b00l34n_sq1i_wh15p3rs_tru7h}`

## What this actually teaches

The lesson isn't "SQL injection is bad" — everyone already knows that.
It's that **a filter is not a fix**. Blocking four specific substrings
stopped the textbook payload and nothing else; the underlying query was
still built by string concatenation, which means it was still
unconditionally exploitable, just with a slightly longer detour to get
there. The real fix is the boring one: parameterized queries, so user
input is never part of the SQL text in the first place. No blocklist
built on top of a concatenated query is ever actually a fix — it's a
speed bump.

The second lesson is about patience with silence. A blind vulnerability
gives you nothing for free. Every character of that flag cost roughly
seven requests and zero error messages. That's the actual skill
PortSwigger's blind SQLi labs are testing — not whether you can
recognize an injection point, but whether you can keep building signal
out of a system that refuses to say anything more than yes or no.
