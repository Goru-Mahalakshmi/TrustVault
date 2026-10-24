# Deploying TrustVault (clean clone -> live HTTPS URL)

Two ways. **Option A (Render, free, no credit card)** is the quickest and is what the challenge suggests. **Option B (your own server)** gives
you the full two-database-role setup. Either way HTTPS is **required** (session cookies are `Secure`).

> **Honesty note:** I could not build Docker images or use Render from the environment where this was written. What *was* run end to end
> against a real PostgreSQL 16: the Render-style start (`sh scripts/start.sh`) with a single database user, a `postgres://` URL, files stored
> in the database, production mode, seeding on start; and, separately, the two-role flow of Option B without Docker. Do the "Verify"
> checklist after you deploy and fix whatever differs.

## Option A: Render (free)
1. Put the project in a GitHub repository (it can stay **private** until the deadline: Render can deploy private repos you connect).
2. Render dashboard -> **New -> Blueprint** -> pick the repo. Render reads `render.yaml`: one free web service (Docker) + one free PostgreSQL.
3. Wait for the first deploy (a few minutes). Open the service URL (e.g. `https://trustvault-xxxx.onrender.com`).
   If the URL differs from `https://trustvault.onrender.com`, edit the `APP_BASE_URL` environment variable to match (used in emailed links).
4. If the service logs `Unsafe production configuration: MASTER_KEY_B64 must be base64 of exactly 32 random bytes`, Render's generated value was not
   a 32-byte key: set your own in *Environment*: `python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`
   (and keep a copy: lose the key and every stored file is unreadable).
5. The first start creates the schema and seeds the demo accounts (see README). To use different demo passwords, set `SEED_PASSWORD_ADMIN_DEMO`,
   `SEED_PASSWORD_OWNER_DEMO`, `SEED_PASSWORD_OWNER_TWO`, `SEED_PASSWORD_VIEWER_DEMO` in *Environment* **before** the first start.
6. Free-tier limits you should know: the service sleeps after ~15 minutes idle (the first request then takes up to a minute; open it yourself before
   a judge does), the free database expires after 30 days, and there is no shell, so use the seeded `admin_demo` as your admin.

What is different from Option B (and why it matters): Render gives **one** database user, so it plays both roles. The audit table is then protected
by the immutability **trigger** only, not by a separate low-privilege role; files are stored **encrypted inside PostgreSQL** (`STORAGE_BACKEND=db`)
because the free tier has no persistent disk. Both are recorded in `THREATS.md` under "Knowingly accepted".

### AI suggestions (optional)
Without a key the endpoint answers `503 AI suggestions are not configured` and nothing else changes. Pick ONE provider style and set the variables in the host's *Environment*:
- **Anthropic:** `ANTHROPIC_API_KEY` (optional `AI_MODEL`).
- **Any OpenAI-compatible provider** (many have free tiers, e.g. Groq, OpenRouter, Mistral, Google's Gemini compatibility endpoint): `AI_PROVIDER=openai_compatible`,
  `AI_API_KEY=...`, `AI_BASE_URL=https://.../v1` (must be https), `AI_MODEL=<model name from that provider's docs>`.
  Free-tier terms, limits and model names change: read the provider's current documentation, do not trust a copy of them here.
Never put a key in the repository; set it only in the host's environment. What is sent to the provider: the document's title and category, and the usernames and past
categories of people the owner has already shared with. Never file contents. Free tiers may log or train on what you send: use fake titles for the demo if that matters to you.

### Verify (both options)
```bash
curl -s https://YOUR_URL/healthz                                  # {"status":"ok"}
curl -sI https://YOUR_URL/healthz | grep -i strict-transport      # HSTS present
curl -s -o /dev/null -w "%{http_code}\n" https://YOUR_URL/docs     # 404 in production (see docs/API_REFERENCE.md instead)
```
In a private/incognito window: log in as `viewer_demo` (exactly one document listed, download works); as `owner_demo` open "Contract - Acme Ltd"
-> the **Activity** tab; as `admin_demo` use **Audit trail -> Verify integrity** (VALID) and the activity filters. Confirm the IP recorded in the
audit log is yours, not a private-range address (if it is, `TRUSTED_PROXIES` does not match the host's proxy).

## Option B: your own server (Docker Compose + Caddy)
Stack: Caddy (automatic HTTPS) -> API (FastAPI, 2 workers) -> PostgreSQL 16, all in Docker Compose on one small Linux server.
HTTPS is **required**: session cookies are `Secure`, so login will not work over plain HTTP.

### B1. Server and domain (10 min)
- Any Ubuntu 24.04 VPS with 1 GB RAM+ (Hetzner, DigitalOcean, Lightsail, Oracle free tier...). Open ports **80 and 443**.
- Point a DNS **A record** (e.g. `vault.yourdomain.com`) at the server's IP. Caddy cannot get a certificate until this resolves.
- Install Docker: `curl -fsSL https://get.docker.com | sh`

### B2. Get the code and configure
```bash
git clone <your-public-repo-url> trustvault && cd trustvault
cp .env.prod.example .env.prod
python3 -c "import secrets;print(secrets.token_hex(24))"                               # run 3x: the three DB passwords
python3 -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"   # MASTER_KEY_B64
python3 -c "import secrets;print(secrets.token_urlsafe(48))"                           # AUDIT_HMAC_KEY
nano .env.prod        # fill DOMAIN, the three passwords, MASTER_KEY_B64, AUDIT_HMAC_KEY, APP_BASE_URL
```
**Back up `MASTER_KEY_B64` and `AUDIT_HMAC_KEY` somewhere that is not this server.** Lose the master key and every stored file is
unreadable; lose the audit key and the audit chain can no longer be verified. The app refuses to start in production if either is
missing, weak, or still a development default.

### B3. Start
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
docker compose -f docker-compose.prod.yml --env-file .env.prod logs -f api     # wait for "Application startup complete"
```
What happens: PostgreSQL starts and creates two roles on first boot -> `migrate` (the only container holding the owner
credential) creates the schema, grants and the audit immutability trigger, then exits -> `api` starts with the restricted app
credential only -> Caddy obtains the TLS certificate.

### B4. Seed demo data (accounts for the judges)
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod run --rm api python -m scripts.seed
```
Safe to run again (idempotent). Demo accounts (passwords are public, see the README; change with `SEED_PASSWORD_<NAME>` env vars
before seeding anything that matters):

| Username | Role | What it demonstrates |
|---|---|---|
| `admin_demo` | admin | user management, audit log, dashboard, chain verification; **no** access to document contents |
| `owner_demo` | owner | owns 3 documents; has an edit grant on one of `owner_two`'s |
| `owner_two` | owner | owns "Site drawings" (2 versions); has read on "Board minutes Q3" |
| `viewer_demo` | viewer | sees exactly one document ("Salary letter"); "Contract - Acme Ltd" is shared with nobody |

### B5. Verify
```bash
curl -s https://YOUR_DOMAIN/healthz                          # {"status":"ok"}
curl -sI https://YOUR_DOMAIN/healthz | grep -i strict-transport
curl -s -o /dev/null -w "%{http_code}\n" https://YOUR_DOMAIN/docs         # 404 in production
```
In a browser: log in as `viewer_demo`, confirm only one document is listed, download it. Log in as `admin_demo`, open
**Audit trail**, click **Verify integrity** (expect VALID). Check the client IP recorded in the audit log is yours, not a `172.x` address;
if it shows a Docker address, `TRUSTED_PROXIES` does not match your Docker network.

### B6. Operations
- **Logs:** `docker compose -f docker-compose.prod.yml logs -f api`
- **Make a real admin:** register in the UI, then
  `docker compose -f docker-compose.prod.yml --env-file .env.prod run --rm api python -m scripts.make_admin YOUR_USERNAME`
- **Audit anchoring** (detects tampering back to the last anchor; clone a *separate* private git repo to `/srv/trustvault-anchors`):
  ```bash
  # crontab -e   (hourly)
  0 * * * * cd /srv/trustvault && docker compose -f docker-compose.prod.yml --env-file .env.prod run --rm -v /srv/trustvault-anchors:/anchors api python -m scripts.anchor_audit /anchors/anchors.log && cd /srv/trustvault-anchors && git add -A && git commit -qm anchor && git push -q
  ```
- **Backups:** `docker compose ... exec db pg_dump -U postgres trustvault > backup.sql` AND the `files` volume (encrypted
  documents). A database backup without the files, or without `MASTER_KEY_B64`, restores nothing readable.
- **Update:** `git pull && docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build` (migrate re-runs; it is idempotent).
- **Email:** `EMAIL_BACKEND=console` prints reset links into the api log (fine for a demo). For real mail set `EMAIL_BACKEND=smtp` + `SMTP_*`.
- **Stop / wipe everything:** `docker compose -f docker-compose.prod.yml down` (add `-v` to delete data).

## Other hosts (Railway, Fly...)
The app only needs: PostgreSQL where you can create two roles, a persistent disk for `STORAGE_DIR`, HTTPS in front, and the env vars
in `.env.prod.example`. Create the roles with `docker/initdb-prod/01_roles.sh` logic by hand, run `python -m scripts.init_db` once
with `OWNER_DATABASE_URL`, then run the app with `DATABASE_URL` pointing at the **app** role. Set `TRUSTED_PROXIES` to your platform's
proxy range, or client-IP rate limiting will see every user as one address.
