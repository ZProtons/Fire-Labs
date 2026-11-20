# Fire-Labs

A collection of intentionally vulnerable web applications and CTF-style labs for practicing web application security.

Each lab lives in its own directory under `labs/`. The applications are independent: they retain their own dependencies, configuration, run instructions, challenge material, and write-ups.

## Labs

| Lab | Focus | Local target |
|---|---|---|
| [insecure-notes](labs/insecure-notes/) | SQL injection, IDOR, stored XSS, SSRF, path traversal, and authentication flaws | http://127.0.0.1:5000 |
| [photovault](labs/photovault/) | File-upload flaws, access-control issues, and upload-to-RCE chains | http://127.0.0.1:5001 |
| [vault-bank-blindsqli](labs/vault-bank-blindsqli/) | Boolean-based blind SQL injection and automated extraction | http://127.0.0.1:5002 |
| [pixelgram](labs/pixelgram/) | Black-box web application challenge with five hidden flags | http://127.0.0.1:5003 |
| [novametrics-recon](labs/novametrics-recon/) | Pure reconnaissance, no exploitation — robots.txt, HTML comments, response headers, exposed .git, sitemap.xml, backup files | http://127.0.0.1:5004 |
| [xss-lab](labs/xss-lab/) | Reflected, stored, and DOM-based XSS, with a filter to route around | http://127.0.0.1:5005 |

## Getting started

Read the README inside the lab you intend to run. Labs have independent setup instructions and dependencies.

For the Docker-based labs:

```bash
docker compose -f labs/insecure-notes/docker-compose.yml up --build
```

Or:

```bash
docker compose -f labs/photovault/docker-compose.yml up --build
```

For the Python-only labs, follow their individual READMEs:

- [Vault Bank](labs/vault-bank-blindsqli/README.md)
- [PixelGram](labs/pixelgram/README.md)

Stop Docker labs with `Ctrl+C`; remove their containers with `docker compose -f <compose-file> down`.

## Repository layout

```text
Fire-Labs/
├── README.md
└── labs/
    ├── insecure-notes/
    ├── photovault/
    ├── vault-bank-blindsqli/
    ├── pixelgram/
    ├── novametrics-recon/
    └── xss-lab/
```

New labs belong in a new directory under `labs/`. Keep each lab self-contained and add a README with its purpose, prerequisites, startup instructions, target URL/port, and safety notes. Keep lab-specific write-ups and supporting files inside that lab's directory.

## Safety

These applications are deliberately vulnerable. Some demonstrate high-impact behavior, including arbitrary file access and remote code execution.

- Run the labs only on your own machine or in an isolated environment you control.
- Keep them bound to localhost or an isolated lab network. Do not expose them to the public internet.
- Do not reuse the included exploit techniques against systems without explicit authorization.
- Treat seeded credentials, flags, and challenge data as lab-only material.
- Stop the applications when you are finished.

## Scope and history

This repository contains snapshots of the current contents of four original repositories. Those original repositories are not modified by this consolidation and remain available as their historical sources:

- https://github.com/ZProtons/insecure-notes
- https://github.com/ZProtons/photovault
- https://github.com/ZProtons/vault-bank-blindsqli
- https://github.com/ZProtons/pixelgram

`novametrics-recon` and `xss-lab` have no separate standalone repository — both were built directly into this collection.

The copied lab files are organized under `labs/<lab-name>/`. Their original commit histories are not combined into this repository.
