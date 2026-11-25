# CSRF — Cross-Site Request Forgery Reference Notes

## 1. What is CSRF?

Cross-Site Request Forgery tricks an authenticated user's browser into making an unwanted request to a web application on their behalf — without them knowing.

The attack exploits the fact that browsers automatically attach cookies (including session cookies) to every request sent to a matching domain, regardless of where the request originated.

**Classic scenario:**
1. Alice is logged into `bank.com` — her session cookie is live in her browser
2. Alice visits `evil.com` (via phishing link, forum post, etc.)
3. `evil.com` contains a hidden form that submits to `bank.com/transfer`
4. Alice's browser sends the request *with her session cookie attached*
5. `bank.com` sees a valid authenticated request and processes the transfer

The server cannot tell the difference between a request Alice intended and one the attacker triggered, because both carry the same cookie.

---

## 2. How browsers make CSRF possible

The root cause is the **same-origin policy gap**: browsers block cross-origin *reads* but allow cross-origin *writes* (form submissions, image loads, script loads). A form on `evil.com` can POST to `bank.com` — the browser won't expose the response, but the action still happens.

**Cookies attach automatically** to any request matching the cookie's domain and path, regardless of which page triggered the request.

---

## 3. Types of CSRF

### 3.1 — Classic GET CSRF
The state-changing action happens on a GET request (worst practice, but it exists).

```html
<!-- Loads silently as an image; browser sends GET with cookies -->
<img src="https://bank.com/transfer?to=attacker&amount=1000">
```

### 3.2 — POST CSRF
More common. A hidden auto-submitting form.

```html
<form action="https://bank.com/transfer" method="POST" id="f">
  <input name="to"     value="attacker">
  <input name="amount" value="1000">
</form>
<script>document.getElementById('f').submit();</script>
```

### 3.3 — JSON CSRF
Applications that accept `application/json` but don't enforce the Content-Type strictly, or accept `text/plain` as a fallback, can be hit with:

```html
<form action="https://api.example.com/update" method="POST"
      enctype="text/plain">
  <!-- name crafted so the whole value decodes as valid JSON -->
  <input name='{"role":"admin","x":"' value='"}'>
</form>
```
Sends: `{"role":"admin","x":""}` as a plain-text body. Some backends parse it anyway.

### 3.4 — Login CSRF
Forces the victim to log in as the attacker's account. After logging in, any activity the victim performs (searches, purchases, notes) is captured in the attacker's account.

### 3.5 — CSRF via XMLHttpRequest / fetch
If CORS is misconfigured to reflect the `Origin` header without credentials check, an attacker page can send credentialed cross-origin XHR. See CORS notes.

---

## 4. What CSRF can and cannot do

| Can do | Cannot do |
|--------|-----------|
| Make requests as the victim | Read responses (blocked by SOP) |
| Change state (password, email, transfer funds) | Steal session tokens directly |
| Click actions (follow, like, post) | Exfiltrate data (unless combined with XSS) |
