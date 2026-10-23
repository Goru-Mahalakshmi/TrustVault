# TrustVault Threat Model & Defensive Matrix

This document details the threat landscape, defensive architecture, concrete tests, and residual risks for TrustVault. Every threat is analyzed from an adversarial perspective ("How it could be broken"), followed by the system's engineering defenses, the automated tests proving immunity, and an honest assessment of residual risk.

> **Status Legend:**
> - `[DESIGNED-ONLY]`: Specification designed, validated in threat model, awaiting phase implementation. `[PARTIAL]`: some controls built and tested, the rest listed in the note.
> - `[BUILT]`: Fully implemented in application code and verified by automated pytest test suite.

---

## 1. Threat Analysis by Vector

### 1.1 Insecure Direct Object References (IDOR / BOLA) & Existence Oracles
- **Status:** `[BUILT]`
- **Exploit Scenario:** An unauthorized user guesses or enumerates document UUIDs. If the server returns `403 Forbidden` for existing documents and `404 Not Found` for nonexistent documents, or if the code paths perform measurably different database work, an attacker can determine which documents exist in the system.
- **Engineering Defense:**
  - All document primary keys are cryptographically random UUIDv4 identifiers.
  - **Identical Work & Identical Status (Consistent 404):**
    - Both nonexistent and unauthorized document paths execute the identical query structure: querying with permission predicates (`WHERE id = :id AND (owner_id = :uid OR id IN (SELECT ...))`).
    - Both paths return identical status (`404 Not Found`) and identical body (`{"detail": "Document not found"}`).
    - Both paths trigger uniform refusal audit logging.
  - **Refusal Rate Limiting with Aggregated Auditing:** Refusal events are rate-limited per IP and per user via database-backed counters. Forwarded IP headers (`X-Forwarded-For`) are trusted only when originating from explicitly configured trusted reverse proxies. When refusal rate limiting kicks in, suppressed refusal attempts are tracked in the rate-limit store and flushed as a single aggregated audit event (`REFUSALS_RATE_LIMITED_AGGREGATE`), ensuring refusals are never silently dropped.
- **Verification Test:** `tests/test_documents.py::test_stranger_and_missing_are_identical_404_and_audited`
- **Residual Risk:** Real-world network jitter and minor database internal caching variations exist. Because queries execute across indexed UUIDs and uniform JSON payloads are returned, external network noise masks database execution variance.

---
- **Implementation note:** Identical status, body and refusal audit are tested; probing is throttled with HTTP 429 (tests/test_documents.py::test_probing_is_throttled_with_429_and_never_silently_dropped); identical DB *timing* is designed but not measured.

### 1.2 Broken Function-Level Authorisation (BFLA) & Role Impersonation
- **Status:** `[BUILT]`
- **Exploit Scenario:** A `viewer` or unprivileged `owner` issues HTTP requests to administrative endpoints (`/api/admin/*`) or document-management endpoints (e.g. an editor calling `DELETE /api/documents/{id}`).
- **Engineering Defense:**
  - Route handlers enforce strict FastAPI dependency injection checking authenticated system roles (`require_role("admin")`).
  - Document-mutating endpoints enforce `authorize(actor, document, Action.DOCUMENT_DELETE)` which strictly requires `actor.id == document.owner_id`.
  - Grants of level `edit` permit only `Action.DOCUMENT_EDIT` (uploading new versions) and reject delete, grant, revoke, transfer, and restore.
- **Verification Test:** `tests/test_documents.py::test_viewer_and_admin_cannot_upload` and `tests/test_routes.py::test_every_route_requires_auth_or_is_explicitly_public`
- **Residual Risk:** Developer adding a new endpoint and omitting the dependency. Mitigated by `tests/test_routes.py::test_endpoint_inventory_has_explicit_auth` which inspects FastAPI's route table at test time and fails the build if any route lacks auth dependencies or explicit `@public` decorator.

---

### 1.3 Mass Assignment & Parameter Tampering
- **Status:** `[BUILT]`
- **Exploit Scenario:** A user registering an account or updating a document injects hidden parameters into the JSON payload (e.g., `{"username": "hacker", "role": "admin"}` or `{"title": "Doc", "owner_id": "victim-id"}`).
- **Engineering Defense:**
  - Strict Pydantic v2 request schemas with `model_config = ConfigDict(extra="forbid")`.
  - Domain models separate input schemas (`UserCreate`, `DocumentCreate`, `GrantCreate`) from internal database models. Sensitive fields like `id`, `role`, `owner_id`, `is_active`, `security_version`, `granted_by` are never accepted from request payloads; they are populated solely by the server from authenticated session context.
- **Verification Test:** `tests/test_mass_assignment.py::test_mass_assignment_on_register_rejected`
- **Residual Risk:** None in API layer. Pydantic strictly validates and rejects unknown keys with HTTP 422 Unprocessable Entity.

---

### 1.4 Path Traversal, Arbitrary File Overwrite & Content-Disposition Injection
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker uploads a file named `../../../../etc/passwd` or injects control characters into `Content-Disposition` (e.g. `filename="test.pdf\"; dummy=\".exe"` or null bytes `invoice.pdf\x00.exe`).
- **Engineering Defense:**
  - Files are stored on disk strictly under random UUIDv4 names: `{document_uuid}_{version_uuid}.enc`.
  - User-supplied filenames are never used in filesystem paths.
  - User filenames are sanitized:
    1. Basename extracted via `os.path.basename`.
    2. Null bytes (`\x00`) and control characters stripped.
    3. Unicode normalized via NFKC.
    4. Only alphanumeric characters, dashes, underscores, and dots are preserved.
  - When served via download, `Content-Disposition` uses RFC 6266 `filename="safe_name"` with double quotes escaped and non-ASCII characters handled via `filename*=UTF-8''...`.
- **Verification Test:** `tests/test_documents.py::test_roundtrip_encrypted_at_rest_and_headers`
- **Residual Risk:** Complex international filenames with non-Latin scripts are normalized and sanitized. Preserving clean UTF-8 representations via RFC 5987 prevents data loss.

---

### 1.5 Stored Cross-Site Scripting (XSS) via Uploads, SVGs & HTML Files
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker uploads an HTML file, SVG with `<script>` tags, or a script file, hoping a user or admin will open it in the browser and execute scripts within TrustVault's origin.
- **Engineering Defense:**
  - Magic-byte content sniffing rejects `text/html`, `application/javascript`, and `image/svg+xml`.
  - Uploaded files are **never** served statically via a web server root or static asset mount.
  - Downloads are forced to attachment mode: `Content-Disposition: attachment; filename="..."`.
  - Direct downloads return:
    - `X-Content-Type-Options: nosniff` (prevents MIME type confusion attacks).
    - `Content-Security-Policy: default-src 'none'; sandbox` (neutralizes script execution even if forced to render inline).
    - `Content-Type: application/octet-stream`.
- **Verification Test:** `tests/test_documents.py::test_upload_validation`
- **Residual Risk:** Client-side zero-day vulnerabilities in local PDF viewing software. Mitigated by enforcing file downloads as attachments with sandbox CSP headers.

---

### 1.6 Upload Validation, Content Sniffing Mismatches & Zip Bombs
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker renames an executable (`malware.exe`) to `document.pdf` to bypass extension checks, or uploads a zip bomb (e.g. 42KB expanding to 4.5TB) inside a `.docx` or `.xlsx` container.
- **Engineering Defense:**
  - **Triple Validation Pipeline:**
    1. File extension checked against an explicit allowlist (`.pdf`, `.png`, `.jpg`, `.jpeg`, `.webp`, `.txt`, `.csv`, `.docx`, `.xlsx`).
    2. Header inspection reads first 4096 bytes to inspect magic signatures.
    3. The detected MIME type must strictly match the declared extension family. Mismatches are rejected with HTTP 400.
  - Executable signatures (`MZ` for PE/Windows, `\x7fELF` for Linux, Mach-O, scripts with `#!`) are categorically rejected.
  - **Decompression-Bomb Guard:** For archive-based formats (`.docx`, `.xlsx`), the archive directory is inspected without decompressing to disk. If compression ratio exceeds 100:1 or total uncompressed size exceeds 100MB, the file is rejected.
  - Hard limit of 25MB enforced during upload streaming.
- **Verification Test:** `tests/test_documents.py::test_upload_validation`
- **Residual Risk:** Zero-day parsing flaws in underlying ZIP parser. Mitigated by inspecting only directory records and never extracting files to disk.

---

### 1.7 Session Fixation, Hijacking, CSRF & Timeout Controls
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker intercepts an unencrypted session cookie, tricks the victim's browser into submitting state-changing requests via CSRF, or uses a stale session after account deactivation.
- **Engineering Defense:**
  - Session IDs are cryptographically random 256-bit tokens stored as SHA-256 hashes (`session_token_hash`).
  - Session cookies configured with: `HttpOnly=True`, `Secure=True`, `SameSite=Strict`.
  - **Session Rotation:** On successful login, prior sessions are rotated/terminated and new session/CSRF tokens are issued.
  - **Dual Timeouts:** Idle timeout after 30 minutes of inactivity; absolute timeout after 12 hours max lifetime.
  - **CSRF Defense:** State-mutating routes (POST, PUT, DELETE, PATCH) verify the `X-CSRF-Token` header against the cryptographically bound CSRF secret in the session record.
  - **Instant Invalidation:** Account disabling, password reset, or role changes increment `user.security_version`, invalidating all active sessions across all devices immediately.
- **Verification Test:** `tests/test_auth_sessions.py (csrf, logout, idle/absolute timeout, password-change invalidation)`
- **Residual Risk:** If an attacker achieves code execution inside the user's browser, they can interact via the active DOM. Mitigated by strict CSP and eliminating XSS sinks.

---

### 1.8 SQL Injection & Search Parameter Manipulation
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker injects SQL fragments into search filters (`category=' OR 1=1 --`) or sorts by malicious clauses (`sort=title; DROP TABLE users;`).
- **Engineering Defense:**
  - 100% parameterised SQL using SQLAlchemy 2.0 Core and ORM statements.
  - Search sorting only allows columns from an explicit allowlist (`title`, `created_at`, `updated_at`, `file_size_bytes`).
  - Search queries strictly enforce permission predicates at the SQL query level:
    ```sql
    WHERE documents.is_deleted = FALSE
      AND (
        documents.owner_id = :user_id
        OR documents.id IN (
            SELECT document_id FROM document_grants 
            WHERE grantee_user_id = :user_id 
              AND revoked_at IS NULL 
              AND (expires_at IS NULL OR expires_at > NOW())
        )
      )
    ```
- **Verification Test:** `tests/test_documents.py::test_search_is_permission_filtered_and_paginated`
- **Residual Risk:** None. All dynamic query parameters are strictly bound via parameterized prepared statements.

---

### 1.9 Brute-Force, Credential Stuffing & User Enumeration
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker automates high-frequency password guessing on `/api/auth/login` or measures response differences between existing and nonexistent accounts.
- **Engineering Defense:**
  - Passwords hashed using Argon2id (`argon2-cffi`).
  - **Account Lockout:** After 5 consecutive failed login attempts, an account is locked for 15 minutes.
  - Database-backed counter rate limiting on auth endpoints (5 attempts per minute per IP). Forwarded IP trusted only from known proxies.
  - Unified error message: Login returns `"Invalid credentials"` regardless of whether the user exists or the password was incorrect.
  - Constant-time password verification: If the user does not exist, a dummy Argon2id hash verification is executed to prevent timing-based username enumeration.
- **Verification Test:** `tests/test_auth_login.py::test_account_lockout_after_consecutive_failures` and `tests/test_auth_rate_limiting.py::test_login_rate_limiting`
- **Residual Risk:** Distributed credential stuffing across rotating residential proxy IPs could bypass per-IP rate limits until individual target accounts lock out.

---
- **Implementation note:** Lockout and rate limits are tested; the constant-time dummy hash exists but response-time uniformity is not measured.

### 1.10 Download Revocation Race Conditions & Real In-Flight Guarantee
- **Status:** `[BUILT]`
- **Exploit Scenario:** An owner revokes a user's grant while the user is downloading a file. If authorization is checked only once early in the request, the user receives data after revocation.
- **Engineering Defense:**
  - **Global Decrypt Concurrency Cap:** In-memory decryptions are guarded by an asynchronous semaphore (`MAX_CONCURRENT_DECRYPTS = 10`) to prevent RAM exhaustion.
  - **Full In-Memory Decryption & Pre-Send Re-Check:**
    1. Ciphertext is loaded from disk and decrypted in memory (up to 25MB ceiling).
    2. AES-256-GCM authentication tag is verified with AAD `document_id:version_id`.
    3. **Immediately before sending the HTTP response body**, the server executes a live database re-check of `authorize(actor, document, Action.DOCUMENT_DOWNLOAD)`.
    4. If the grant was revoked or the user was disabled while decryption occurred, the response is aborted and HTTP 404 is returned. Zero payload bytes are released.
  - **Download Audit Semantics:** Audit event `DOCUMENT_DOWNLOAD` formally records that the payload was **released by the server**, not that the client confirmed receipt.
  - **The Real Guarantee:**
    - **No new bytes after the revocation commits.**
    - Any request arriving after a revocation transaction commits receives `404 Not Found`.
    - If a request already passed the pre-send check and the web server began writing bytes to the TCP socket buffer before the revocation transaction committed, those buffered bytes will finish sending. However, no subsequent request or version can be initiated.
- **Verification Test:** `tests/test_documents.py::test_revoked_mid_download_releases_zero_bytes`
- **Residual Risk:** TCP socket buffers in the operating system kernel: once IP packets leave the server network interface, bytes in transit cannot be recalled. Mitigated by checking authorization immediately prior to response dispatch.

---

### 1.11 Soft-Deleted Documents & Grant Restore Semantics
- **Status:** `[BUILT]`
- **Exploit Scenario:** An owner soft-deletes a document, but an attacker with an existing direct link or grant continues to access it, or prior grants behave unpredictably when restored.
- **Engineering Defense:**
  - `documents.is_deleted = TRUE` immediately removes the document from all searches, listings, and grantee views.
  - In `authorize()`, if `document.is_deleted == TRUE`, any request from a grantee returns `404 Not Found`.
  - Only the `owner_id` can access `POST /api/documents/{id}/restore`.
  - **Grant Preservation Rule:** Soft-deleting a document disables grantee access. When the owner restores the document, prior unrevoked grants become active again **provided they have not expired** (`expires_at > NOW()`). Grants that expired during deletion remain expired; grants revoked before deletion remain revoked.
- **Verification Test:** `tests/test_documents.py::test_soft_delete_restore_preserves_grants`
- **Residual Risk:** Residual encrypted files remain on disk until permanent purge/hard-delete is invoked. Mitigated by keeping DEKs encrypted at rest.

---

### 1.12 Ownership Transfer Hijacking & Hostile Document Dumping
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker transfers an illegal or sensitive document to a victim's account without consent, or an owner transfers ownership but retains ghost access.
- **Engineering Defense:**
  - **Two-Step Ownership Transfer:** Direct unilateral transfer is prohibited.
    1. Recipient must hold system role `owner` (`role == 'owner'`).
    2. Owner calls `POST /api/documents/{id}/transfer-request` specifying `target_user_id`. The document sets `pending_owner_id`. The owner retains full control while pending.
    3. **Pre-Acceptance Isolation:** The recipient can only see the document ID, category, and transferring owner's username in their pending transfers list. They cannot access contents, versions, or files.
    4. The designated recipient must explicitly call `POST /api/documents/{id}/transfer-accept`.
    5. Transfer executes atomically: sets `owner_id = pending_owner_id`, clears `pending_owner_id = NULL`.
    6. **Old Owner Retention:** The old owner retains **nothing** unless re-granted by the new owner.
    7. **Grants Continuity:** Grants issued by the old owner remain in effect on the document. Any grant recipient held is revoked.
    8. **Cancellation Rules:** Soft-deleting the document while pending cancels the transfer. Deactivating the recipient user account invalidates acceptance. Recipient can reject (`transfer-reject`) and owner can cancel (`transfer-cancel`).
- **Verification Test:** `tests/test_documents.py::test_two_step_transfer`
- **Residual Risk:** None. State transitions are atomic and require mutual participation.

---

### 1.13 Cryptographic Audit Trail Integrity & HMAC-SHA256 Chaining
- **Status:** `[PARTIAL]`
- **Exploit Scenario:** An attacker modifies audit rows to conceal unauthorized access, or a database lock deadlock occurs between actions and refusal logging.
- **Engineering Defense:**
  - **Role Bifurcation:** `trustvault_owner` (runs migrations, DDL, triggers) vs `trustvault_app` (runtime app: `INSERT, SELECT` on `audit_logs`). App role cannot alter tables or triggers.
  - **Immutable DB Trigger:** Unconditional trigger raises exception on `UPDATE` or `DELETE`.
  - **HMAC-SHA256 Hash Chain:** Each row computes:
    $$\text{row\_hash}_n = \text{HMAC-SHA256}\left(K_{\text{audit}}, \text{prev\_hash}_{n-1} \parallel \text{CanonicalPayload}_n\right)$$
  - **Advisory Transaction Locking (`pg_advisory_xact_lock`):** Taken late in the transaction immediately before commit. Previous hash is read directly from the last row in `audit_logs`.
  - **ID-Only Audit Metadata:** Audit metadata stores IDs only (`document_id`, `version_id`, `user_id`, `grant_id`). Filenames, titles, and search queries are excluded, preventing log injection and metadata leakage.
  - **Deadlock-Free Denial Logging:** If an action is denied, the main request transaction is rolled back first to release all locks, and the refusal log is committed in an **independent, isolated database session**. The refusal transaction can never wait on a lock held by the same request.
  - **External Anchoring to Separate Git Repository / Email:** Periodic cron job writes latest hash to a separate external git repository or authenticated email.
- **Verification Test:** `tests/test_documents.py::test_admin_audit_endpoints_and_tamper_detection`
- **Residual Risk:** See Section 2 (Honest PostgreSQL Superuser Threat Model & Key Exposure).

---
- **Implementation note:** BUILT: HMAC chain, tamper detection, isolated refusal logging (tests/test_documents.py::test_refusal_never_waits_on_a_lock_held_by_the_same_request), DB-backed refusal rate limit with aggregate event. NOT YET RUN: `docs/postgres_audit_hardening.sql` (role split + immutable trigger, needs PostgreSQL) and `scripts/anchor_audit.py` scheduling.

### 1.14 User Lookup for Granting & Enumeration Trade-Off
- **Status:** `[BUILT]`
- **Exploit Scenario:** An attacker uses the grant creation interface to enumerate registered user accounts by testing different email addresses.
- **Engineering Defense:**
  - Grant creation requires the owner to input the **exact email address** (`grantee_email`).
  - Prefix searches, wildcard queries, and public user directories are strictly prohibited.
  - **Accepted Trade-Off:** If an owner inputs an email that is not registered, the server returns `404 Not Found` ("Target user not found"). This enables an authenticated owner to test whether an email has an account on the platform.
  - **Mitigation:**
    - Restricted exclusively to authenticated users with the `owner` role.
    - Grant creation attempts are rate-limited per owner (max 10 attempts/min).
    - Failed lookups generate `PERMISSION_GRANT_FAILED` audit events.
- **Verification Test:** `tests/test_documents.py::test_grant_rules`
- **Residual Risk:** An authorized owner could slowly verify whether a specific known email address has an account on TrustVault. Acceptable within a secure collaboration platform.

---
- **Implementation note:** Per-owner grant rate limit is implemented but has no dedicated test yet.

### 1.15 Administrative Privilege Abuse & Backdoor Resets
- **Status:** `[BUILT]`
- **Exploit Scenario:** A rogue administrator directly overwrites a user's password or email to hijack their account and view granted documents.
- **Engineering Defense:**
  - **No Direct Password Setting:** Administrators have **zero capability** to set or overwrite user passwords.
  - **Admins Cannot Edit User Emails:** Administrators cannot edit or update user email addresses.
  - **Self-Service Email Changes:** Changing email requires the current password and confirmation via token sent to the **old email address**.
  - **Generic Reset Responses:** Forgot password responses are always uniform and generic (`"If an account exists for that email, password reset instructions have been sent"`).
  - **Security Version Increment:** A completed password reset or password change increments `users.security_version`, immediately invalidating all active sessions across all devices.
  - **Audit Flagging:** Role modifications, account disabling, and password reset dispatches are flagged as "worth noticing" events on the admin dashboard.
  - **Zero Document Access:** Admins have no inherent read or download access to any document.
- **Verification Test:** `tests/test_admin_user_management.py::test_admin_trigger_reset_cannot_set_password`
- **Residual Risk:** An admin with access to the user's external email mailbox could intercept a reset token. Mitigated by external email provider MFA and audit logging.

---

## 2. Knowingly Accepted Residual Risks & Honest Attack Limitations

| Threat | Accepted Residual Risk | Honest Technical Reality & Compensating Control |
| :--- | :--- | :--- |
| **Application Host Compromise & HMAC Key Exposure** | If an attacker achieves remote code execution on the application server host or extracts environment secrets, they obtain `AUDIT_HMAC_KEY`. | **Honest Reality:** The HMAC key lives with the application environment. If the application environment itself is compromised, an attacker possessing both the application secrets and PostgreSQL superuser credentials can forge HMAC entries. **Compensating Control:** External anchoring (to an external Git repo or email) creates an immutable boundary outside both the app host and DB; any historical forging performed after an anchor is taken will be detected when recomputing history against the external anchor. |
| **External Anchoring Window of Vulnerability** | Tampering that occurs *between* scheduled external anchors is not covered by the external anchor until the next anchor is committed. | **Honest Reality:** External anchoring is periodic. Between anchors, chain verification relies solely on the HMAC key. If an attacker tampers with rows before an external anchor runs and lacks `AUDIT_HMAC_KEY`, the HMAC chain fails immediately. If the attacker also stole the HMAC key, they could forge un-anchored rows until the next anchor. |
| **PostgreSQL Database Superuser (`postgres`)** | A database administrator with superuser credentials can drop tables, truncate `audit_logs`, disable triggers, or read raw ciphertext and DEKs. | **Honest Reality:** No application software can prevent a database superuser from modifying the database engine or storage directly. **However**, because TrustVault uses **HMAC-SHA256 with an external key (`AUDIT_HMAC_KEY`)**, a DB superuser *without* app secrets *cannot* rewrite audit history and forge valid hashes. |
| **In-Flight Network Packet Delivery** | If a grant is revoked while response bytes are being written to the network socket, packets already in kernel flight will reach the client. | **Honest Reality:** TCP packets that have left the NIC cannot be recalled. **Compensating Control:** The live grant is re-checked immediately before releasing response bytes. Once revocation commits, zero new bytes or subsequent requests are permitted. |
| **User Enumeration by Authenticated Owners during Granting** | An owner granting access can test whether an exact email address exists on the platform via the 404 response. | **Honest Reality:** Secure document sharing requires addressing a recipient. Hiding whether the recipient exists would require silent failure (fake grants that never arrive), which destroys usability. **Compensating Control:** Strict exact-match email requirements, no autocomplete/wildcards, and rate-limiting per owner. |
| **Argon2id CPU/Memory Consumption** | Argon2id is intentionally resource-intensive; concurrent requests consume CPU and RAM. | **Compensating Control:** Database-backed counter rate limiting (5 attempts/min per IP) applied before password hashing is invoked. |


## Phase 1 update (PostgreSQL baseline, auth and rate limiting)
- **Test database:** the suite now runs on PostgreSQL 16 as the restricted app role. Audit grants, immutability trigger and
  advisory locking are exercised for real (`tests/test_documents.py::test_app_role_cannot_modify_audit_rows`,
  `::test_immutability_trigger_blocks_even_the_owner`, `::test_deliberate_trigger_bypass_is_still_detected_by_the_chain`).
- **Fixed, with failing-first tests (`tests/test_phase1_attacks.py`):** leftmost X-Forwarded-For was spoofable; the rate-limit
  counter was not atomic (lost updates, and a crash on first-hit race); parallel wrong passwords bypassed lockout; a process-wide
  asyncio lock could deadlock against the PostgreSQL advisory lock; disabled-account state was probeable without the password;
  `transfer-accept` returned 403 for non-recipients (existence oracle), now 404.
- **Previously vacuous tests fixed:** the route inventory saw 1 of 32 routes (FastAPI hides included routers); the "admin has no
  password route" test could not fail. Both now have a negative control or a size guard.

## Knowingly accepted
- Registration returns 409 for a taken username/email (account enumeration). Reason: usability of sign-up; mitigated by rate limits.
- Account lockout lets an attacker who knows a username lock that user out for the lockout window. Reason: brute-force protection
  is worth more than availability of a single account; the owner can reset via email, admins can see lock events.
- Correct IP attribution depends on TRUSTED_PROXIES matching the real proxy. Reason: no way to verify headers otherwise.
- CSRF token is held in sessionStorage by the UI. Reason: single-page app without server-rendered pages; CSP is the mitigation.


## Phase 2/3 update (documents, search, isolation, mutation check)
- **Reaching a document through any route:** `tests/test_isolation.py` discovers every route taking a document id and attacks it
  as another owner, a viewer and an admin; after revocation, after expiry, while soft-deleted, and after a role change; it also
  checks nothing was modified. A route-table test fails if a new document route is not added to the suite.
  `[BUILT]` Residual: it covers the states I thought of; routes that take document ids another way (not `{doc_id}`) would not be discovered.
- **Search / listing / counts / facets leaking existence:** the permission predicate is inside every query
  (`tests/test_search_and_versions.py`). `[BUILT]` Residual: result *timing* is not measured.
- **Version history:** same gate as the latest version; old versions readable by anyone who can read the document (accepted, see README).
- **Upload attacks:** null bytes, RTL-override names, double extensions, spoofed magic bytes, scripts, SVG/HTML, oversize, hostile filenames
  (`tests/test_upload_attacks.py`). `[BUILT]` Residual: docx/xlsx are only checked for a ZIP header and bomb ratio, not full OOXML structure;
  no antivirus; whole upload is read into memory (25 MB cap) before validation.
- **"Judge removes one authorisation check":** `scripts/mutation_check.py` (77 mutants: every `authorize()` call site plus 61 other checks).
  Result in `MUTATION_REPORT.md`: 77/77 killed. What it found: the first run of the suite let several mutants survive.
  Six genuine test gaps were closed (restore of a live document, demoted transfer recipient, transfer to self, expired grants in search,
  filename sanitiser, and no-decryption-before-authorisation), and two mutants survived only because a second layer repeated the check
  (download `nosniff` header also set by middleware; disabled-user check also covered by the security_version bump) - each layer now has its
  own test. `[BUILT]` Residual: mutants are my own list; a different weakening of the same line is not proven caught.
- **Defence in depth made explicit:** downloads are gated twice (first gate before any file read, pre-send re-check on a fresh connection);
  sessions die on security_version bump AND on `is_active=false`.

## Deployment (Phase 4)
- **Weak production secrets / missing master key:** the app refuses to start in production with a development audit key, a missing or
  wrong-length master key, insecure cookies or SQLite (`tests/test_deploy_config.py`). `[BUILT]`
- **Owner credential exposure:** only the one-shot `migrate` container holds the owner database credential; the API runs with the
  restricted app role. `[BUILT]` in `docker-compose.prod.yml`; not exercised in a Docker build here (`[DESIGNED-ONLY]` as a container
  arrangement; the same role split is tested on PostgreSQL).
- **Client-IP spoofing behind the reverse proxy:** rightmost-untrusted-hop with CIDR-aware `TRUSTED_PROXIES`
  (`tests/test_deploy_config.py::test_trusted_proxy_can_be_a_cidr_range`, `tests/test_phase1_attacks.py`). `[BUILT]`
  Residual: the default Docker private ranges trust every container on that network; only Caddy and the API share it.
- **Attack surface:** `/docs` and `/openapi.json` are off in production; HSTS is sent; `Server` header removed. `[BUILT]`

### Knowingly accepted (deployment)
- The demo passwords are public in the README because judges need credentials. Reason: the data is fake and the accounts cannot exceed
  their roles; the admin demo can read the audit log and manage users, so rotate `SEED_PASSWORD_*` or delete the demo users after judging.
- Losing `MASTER_KEY_B64` makes every document permanently unreadable, and losing `AUDIT_HMAC_KEY` ends chain verification. Reason: keys
  must not live in the database; backing them up elsewhere is the operator's job (DEPLOY.md says so).
- Email defaults to console output in the demo deployment, so reset links appear in server logs. Reason: no mail account was provisioned.
- Single server, no high availability, no automated backups. Reason: scope of a one-week build; backup commands are documented.

## AI suggestions (Phase 5)
- **The model widens access by itself:** suggesting creates no grant; access only follows the owner's per-person decision through the same grant
  code as a manual grant (`tests/test_ai_decisions.py::test_full_flow_...`, mutant "ai: suggestions auto-applied as grants"). `[BUILT]`
- **Hallucinated or malicious ids from the model:** ids must be previous grantees of this owner; others are dropped, and a decision naming anyone the AI
  did not suggest is a 404 (`..._never_suggested_cannot_be_granted...`). `[BUILT]`
- **Prompt injection through titles, categories or model output:** document text is JSON-escaped with `<`/`>` neutralised so it cannot close the data
  delimiter; injected fields in model output are ignored; reasons are inert text (UI uses textContent). `[BUILT]` Residual: injected text can still
  *influence which already-valid candidate is suggested*; that is why a human decides, and why it is audited.
- **Forged or mislabelled decisions:** the client cannot send the label (extra fields are 422); the server derives accepted/modified. A suggestion cannot be
  replayed on another document or by another owner; each person can be decided once. `[BUILT]`
- **Audit of the AI path:** request, each suggested person, each decision and resulting grant, ids only. `[BUILT]` Residual: the model's reason text is stored
  in `ai_suggestions` (mutable app data), not in the hash-chained audit.
- **Knowingly not built:** an owner opt-in to send more than title/category to the model (nothing else is ever sent).
