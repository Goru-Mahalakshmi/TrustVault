# Walkthrough: how authorisation works (for the interview)

You will be asked: *"Where is the authorisation decision made when someone downloads a file, and what happens if that line is removed?"*
Know this file. Open the code next to it. Everything here points at real functions.

## 1. A download, step by step (`GET /api/documents/{id}/download`)
1. `src/api/deps.py::current_auth` : who is calling? Looks up the session cookie by hash, rejects revoked / expired / idle sessions, rejects a user who is
   disabled or whose `security_version` changed (role change, disable, password change), checks CSRF on unsafe methods. No session -> `401`.
2. `src/api/documents.py::download_document` calls **`authorize(db, ctx, request, doc_id, Action.DOWNLOAD)`** (first gate).
3. `src/services/authz.py::authorize` -> `decide()`: **one SQL query**: the document with this id *and* (owner is me *or* I have a live grant), where a live grant is
   not revoked and not expired (`expires_at > now()` on the **database** clock), and not soft-deleted. No row -> `notfound`. A row -> allow, or `forbid` if my
   grant level is too low for the action (`LEVEL_ACTIONS`). Anything not listed there is owner-only by default (deny by default).
4. On `notfound`/`forbid`, `_refuse()` **rolls back first**, then writes the refusal in a separate transaction (`audit_service.log_refusal_status`, rate-limited per IP and
   per user), then raises `404 Document not found` (or `403` when a relationship exists, `429` when probing is being throttled).
5. `_release()` reads the ciphertext, decrypts **in memory** (`core/crypto.py::decrypt_file`; the GCM tag is verified, the AAD binds it to `document_id:version_id`).
6. **Second gate:** `authz.py::still_authorized` runs on a **fresh database connection**: user still active, session still valid, grant still live. If revoked in the
   meantime -> `404`, zero bytes sent.
7. Only then the audit row `DOCUMENT_DOWNLOAD` is written in the same transaction (meaning *released*, not merely requested) and the bytes are returned with
   `Content-Disposition: attachment`, `nosniff`, a sandboxing CSP and `no-store`.

## 2. "What if that line is removed?"
- Remove step 2 (the first `authorize`): a stranger is still refused at step 6, so the **response** is unchanged, but the file would be read and decrypted for an
  unauthorised caller and the audit would blame the wrong gate. `tests/test_isolation.py::test_unauthorised_requests_are_stopped_before_any_decryption` fails.
- Remove both gates: any signed-in user could download any document id. `tests/test_isolation.py::test_user_b_cannot_reach_user_a_document_on_any_route`
  fails for every download route.
- `python -m scripts.mutation_check` does exactly this for every call site (and many other checks) and reports any change the tests do not notice. Read `MUTATION_REPORT.md`.

## 3. The permission model in plain words
Per-document grants only. Owner or grantee, nothing else. No folders, no groups, no inheritance. Categories are search labels. Admins run accounts and read the audit
log but cannot open a document unless an owner grants it to them like to anyone. Missing document, ungranted document and admin-without-grant all answer the same
`404` with the same work done and the same audit behaviour, so ids cannot be probed.

## 4. What "revoked immediately" means and what it costs
There are no download links or tokens to expire. Every request re-asks the database, so a revoke (`document_grants.revoked_at`) applies to the next request and to a
download already in progress (step 6). Cost: one database round trip per request, and sessions live in the database (no stateless JWTs). Disabling a user, changing a
role or resetting a password bumps `users.security_version`, which invalidates every existing session at once.

## 5. The audit trail
`services/audit_service.py::log_event` appends a row whose hash is `HMAC-SHA256(AUDIT_HMAC_KEY, previous_hash || canonical row)`. PostgreSQL serialises writers with
`pg_advisory_xact_lock`, taken as late as possible. Successful actions write their row in the **same transaction** as the action; refusals are written in their own
transaction after the request is rolled back (so they never wait on a lock the request holds). `verify_audit_chain` walks the chain and reports the first broken link.
What stops alteration: the app role cannot UPDATE/DELETE (`db/hardening.sql`), a trigger blocks it even for the owner, the key is not in the database, and
`scripts/anchor_audit.py` can publish the latest hash elsewhere. What does NOT: someone with the owner role **and** the key can rewrite everything;
anchoring only detects tampering back to the last anchor.

## 6. Storage and crypto
Files are never served from disk. Each version has its own random 256-bit key; the file is AES-GCM encrypted with that key; the key is wrapped by the master key
(`MASTER_KEY_B64`, environment only). Storage names are random UUIDs, never the user's filename (`disk`), or the ciphertext is a database column (`db`).

## 6b. Small changes an interviewer might ask for (and what should fail)
| Change | Where | A test that should notice |
|---|---|---|
| Let `edit` grantees also delete | `authz.py::LEVEL_ACTIONS` add `Action.DELETE` to `"edit"` | `test_grant_levels_and_instant_revocation`, isolation suite |
| Shorten the idle timeout | `core/config.py::SESSION_IDLE_TIMEOUT_MINUTES` | `tests/test_auth_sessions.py::test_idle_timeout_invalidates_session` still passes (it rewinds 31 min) |
| Add a new document action | add to `Action`, call `authorize(...)` in the route, add it to `PAYLOADS` in `tests/test_isolation.py` | `test_payload_table_covers_every_document_route` fails until you do |
| Make search case-sensitive | `documents.py::list_documents` (`ilike` -> `like`) | `test_search_by_name_is_case_insensitive_and_wildcards_are_literal` |
| Add an audit event | call `audit(db, ctx, request, "NAME", ...)`; regenerate `docs/API_REFERENCE.md` | `tests/test_docs_current.py::test_api_reference_is_current` |

## 7. Where I would attack it (weak points, all written up in THREATS.md)
Stored-XSS in the UI (CSRF token in `sessionStorage`), shallow `.docx/.xlsx` validation, no storage quota, timing differences between 404 paths (equal by
construction, not measured), the HMAC key and the database owner role being the crown jewels, and free-tier hosting where one database user plays both roles.
