# Deploying TrustVault (clean clone -> live HTTPS URL)

Stack: Caddy (automatic HTTPS) -> API (FastAPI, 2 workers) -> PostgreSQL 16, all in Docker Compose on one small Linux server.
HTTPS is **required**: session cookies are `Secure`, so login will not work over plain HTTP.

> **Honesty note:** the Docker images and Caddy config were written and the compose file validated, but I could not build
> Docker images in the environment where this was authored. The application steps themselves (migrate as owner role -> seed ->
> run as app role with 2 workers, in `ENVIRONMENT=production`) were run end to end against a real PostgreSQL 16. Do the
> "Verify" checklist below on your server before you rely on it, and fix anything that differs.

## 1. Server and domain (10 min)
- Any Ubuntu 24.04 VPS with 1 GB RAM+ (Hetzner, DigitalOcean, Lightsail, Oracle free tier...). Open ports **80 and 443**.
- Point a DNS **A record** (e.g. `vault.yourdomain.com`) at the server's IP. Caddy cannot get a certificate until this resolves.
- Install Docker: `curl -fsSL https://get.docker.com | sh`

## 2. Get the code and configure
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

## 3. Start
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
docker compose -f docker-compose.prod.yml --env-file .env.prod logs -f api     # wait for "Application startup complete"
```
What happens: PostgreSQL starts and creates two roles on first boot -> `migrate` (the only container holding the owner
credential) creates the schema, grants and the audit immutability trigger, then exits -> `api` starts with the restricted app
credential only -> Caddy obtains the TLS certificate.

## 4. Seed demo data (accounts for the judges)
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

## 5. Verify (do all of these)
```bash
curl -s https://YOUR_DOMAIN/healthz                          # {"status":"ok"}
curl -sI https://YOUR_DOMAIN/healthz | grep -i strict-transport
curl -s -o /dev/null -w "%{http_code}\n" https://YOUR_DOMAIN/docs         # 404 in production
```
In a browser: log in as `viewer_demo`, confirm only one document is listed, download it. Log in as `admin_demo`, open the admin
panel, click **Verify audit chain** (expect VALID). Check the client IP recorded in the audit log is yours, not a `172.x` address;
if it shows a Docker address, `TRUSTED_PROXIES` does not match your Docker network.

## 6. Operations
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

## Other hosts (Render, Railway, Fly...)
The app only needs: PostgreSQL where you can create two roles, a persistent disk for `STORAGE_DIR`, HTTPS in front, and the env vars
in `.env.prod.example`. Create the roles with `docker/initdb-prod/01_roles.sh` logic by hand, run `python -m scripts.init_db` once
with `OWNER_DATABASE_URL`, then run the app with `DATABASE_URL` pointing at the **app** role. Set `TRUSTED_PROXIES` to your platform's
proxy range, or client-IP rate limiting will see every user as one address.
