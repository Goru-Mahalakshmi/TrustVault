# TrustVault: API Specification & Security Contract

Every endpoint in TrustVault enforces explicit authentication dependencies or is explicitly marked as public. All requests except public endpoints require an active session and valid `X-CSRF-Token` on state-mutating methods.

---

## 1. Authentication & Session Management

### `POST /api/auth/register`
- **Access:** Public (Rate-limited: 5 req/min per IP via DB-backed counter)
- **Role:** Any
- **Server Checks:**
  - Valid email and username formats.
  - Password strength validation (min 10 chars, upper, lower, digit, symbol).
  - Argon2id password hash generation.
  - Generates user with default role `owner` (role cannot be supplied by client; extra fields forbidden).
- **Audit Event:** `AUTH_REGISTER` (metadata: `{user_id}`)
- **Response Codes:**
  - `201 Created`: User successfully registered.
  - `400 Bad Request`: Validation failure.
  - `409 Conflict`: Username or email already registered (timing-safe).
  - `429 Too Many Requests`: Rate limit exceeded.

### `POST /api/auth/login`
- **Access:** Public (Rate-limited: 5 req/min per IP via DB-backed counter)
- **Role:** Any
- **Server Checks:**
  - Client IP extracted from `X-Forwarded-For` only if connection is from a configured trusted proxy; otherwise `request.client.host`.
  - Checks if user account is locked (`locked_until > NOW()`).
  - Argon2id password verification (constant-time dummy check if user not found).
  - On failure: increments `failed_login_attempts`; locks for 15 mins if >= 5 attempts. Refusals rate-limited.
  - On success: rotates/terminates prior active sessions, creates new session with idle (30m) and absolute (12h) timeouts, sets `httpOnly` session cookie, returns CSRF token in response body.
- **Audit Event:** `AUTH_LOGIN_SUCCESS` (metadata: `{user_id, session_id}`) / `AUTH_LOGIN_FAILURE` (metadata: `{attempted_username}`)
- **Response Codes:**
  - `200 OK`: Authenticated, session cookie set, CSRF token returned in body.
  - `401 Unauthorized`: `"Invalid credentials"` (unified message, no user enumeration).
  - `423 Locked`: `"Account temporarily locked due to repeated failed attempts"`.
  - `429 Too Many Requests`: Rate limit exceeded.

### `POST /api/auth/logout`
- **Access:** Authenticated
- **Role:** Any
- **Server Checks:**
  - Validates session; marks `session.revoked_at = NOW()`.
  - Clears session cookie.
- **Audit Event:** `AUTH_LOGOUT` (metadata: `{session_id}`)
- **Response Codes:**
  - `200 OK`: Logged out.
  - `401 Unauthorized`: Invalid/expired session.

### `POST /api/auth/forgot-password`
- **Access:** Public (Rate-limited: 3 req/hour per IP/email via DB-backed counter)
- **Role:** Any
- **Server Checks:**
  - Accepts email address.
  - If account exists: generates single-use 15-minute token, hashed via SHA-256 in `password_reset_tokens`. Dispatches reset link to user email.
  - Response is always identical and generic to prevent user enumeration.
- **Audit Event:** `AUTH_RESET_REQUESTED` (metadata: `{user_id}` if found)
- **Response Codes:**
  - `200 OK`: `"If an account exists for that email, password reset instructions have been sent."`
  - `429 Too Many Requests`: Rate limit exceeded.

### `POST /api/auth/reset-password`
- **Access:** Public
- **Role:** Any
- **Server Checks:**
  - Accepts reset token and new password.
  - Validates token: `used_at IS NULL AND expires_at > NOW()`.
  - Hashes new password with Argon2id.
  - Marks `token.used_at = NOW()`.
  - Increments `user.security_version` to immediately invalidate all existing sessions across all devices.
- **Audit Event:** `AUTH_RESET_COMPLETED` (metadata: `{user_id}`)
- **Response Codes:**
  - `200 OK`: Password reset successfully.
  - `400 Bad Request`: Invalid or expired reset token.

### `POST /api/auth/change-password`
- **Access:** Authenticated
- **Role:** Any
- **Server Checks:**
  - Validates current password via Argon2id.
  - Validates and hashes new password.
  - Increments `user.security_version` to invalidate other active sessions.
  - Rotates current session token.
- **Audit Event:** `AUTH_PASSWORD_CHANGED` (metadata: `{user_id}`)
- **Response Codes:**
  - `200 OK`: Password changed.
  - `400 Bad Request`: Invalid current password or weak new password.

### `POST /api/auth/email-change-request`
- **Access:** Authenticated
- **Role:** Any
- **Server Checks:**
  - Validates current password via Argon2id.
  - Validates new email format and uniqueness.
  - Generates single-use 15-minute token in `email_change_tokens`.
  - Dispatches verification token to the **old (current) email address**.
- **Audit Event:** `AUTH_EMAIL_CHANGE_REQUESTED` (metadata: `{user_id}`)
- **Response Codes:**
  - `200 OK`: Confirmation token dispatched to current email address.
  - `400 Bad Request`: Invalid password or email in use.

### `POST /api/auth/email-change-confirm`
- **Access:** Authenticated
- **Role:** Any
- **Server Checks:**
  - Validates token: `used_at IS NULL AND expires_at > NOW()`.
  - Updates `users.email = new_email`.
  - Marks `token.used_at = NOW()`.
  - Increments `user.security_version` to invalidate existing sessions across devices.
- **Audit Event:** `AUTH_EMAIL_CHANGED` (metadata: `{user_id}`)
- **Response Codes:**
  - `200 OK`: Email address updated.
  - `400 Bad Request`: Invalid or expired token.

### `GET /api/auth/me`
- **Access:** Authenticated
- **Role:** Any
- **Server Checks:**
  - Returns current user profile, active role, and fresh CSRF token.
- **Response Codes:**
  - `200 OK`: User details (`id`, `username`, `email`, `role`).
  - `401 Unauthorized`: Not authenticated.

---

## 2. Documents & Content Delivery

### `POST /api/documents`
- **Access:** Authenticated
- **Role:** `owner` (system role)
- **Server Checks:**
  - Upload validation (file size <= 25MB).
  - Extension allowlist + magic byte sniffing match check.
  - Executable, script, HTML, SVG rejection.
  - Zip-bomb decompression check (ratio < 100:1, total uncompressed < 100MB).
  - Generates ephemeral DEK, encrypts payload via AES-256-GCM with AAD `document_id:version_id`.
  - Stores encrypted DEK with master key in DB; ciphertext stored outside web root under random UUID name.
- **Audit Event:** `DOCUMENT_UPLOAD` (metadata: `{document_id, version_id, version_number: 1}`)
- **Response Codes:**
  - `201 Created`: Document created.
  - `400 Bad Request`: File validation failure.
  - `403 Forbidden`: `viewer` role attempting upload.
  - `413 Payload Too Large`: Exceeds 25MB ceiling.

### `GET /api/documents`
- **Access:** Authenticated
- **Role:** Any (`admin`, `owner`, `viewer`)
- **Server Checks:**
  - Filtered strictly at the SQL level: returns only documents where `owner_id = :user_id` OR `id IN (SELECT document_id FROM document_grants WHERE grantee_user_id = :user_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()))`.
  - Admins do NOT see documents without explicit grant.
  - Soft-deleted documents excluded from standard search.
  - Allowlisted sort columns (`created_at`, `updated_at`, `file_size_bytes`).
- **Audit Event:** `SEARCH_QUERY` (metadata: `{filter_category: ...}`)
- **Response Codes:**
  - `200 OK`: List of accessible documents with pagination totals.

### `GET /api/documents/{id}`
- **Access:** Authenticated
- **Role:** Any
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_READ)`
  - If no grant and not owner -> Returns `404 Not Found`.
  - If soft-deleted -> Returns `404 Not Found`.
- **Audit Event:** `DOCUMENT_VIEW` (metadata: `{document_id}`) on allow; `ACCESS_REFUSED` (metadata: `{document_id, action: "read"}`) on deny.
- **Response Codes:**
  - `200 OK`: Document metadata (ID, category, versions count, created_at).
  - `404 Not Found`: Document not found or access ungranted.

### `GET /api/documents/{id}/download`
- **Access:** Authenticated (via session cookie + `X-CSRF-Token`)
- **Role:** Any
- **Server Checks:**
  1. Initial `authorize(user, doc, Action.DOCUMENT_DOWNLOAD)` verification.
  2. Acquire concurrency permit (max 10 concurrent in-memory decryptions).
  3. Decrypt DEK using `MASTER_KEY`.
  4. Decrypt ciphertext fully in memory using AES-256-GCM with AAD `document_id:version_id`.
  5. Verify GCM authentication tag.
  6. Re-check `authorize()` immediately before responding. If revoked or user disabled, abort and return 404 (zero payload bytes released).
  7. Record audit event `DOCUMENT_DOWNLOAD` (signifies payload was *released* by server).
  8. Return payload with attachment headers (`nosniff`, `sandbox` CSP). Release concurrency permit.
- **Audit Event:** `DOCUMENT_DOWNLOAD` (metadata: `{document_id, version_id}`) on allow; `ACCESS_REFUSED` (metadata: `{document_id, action: "download"}`) on deny.
- **Response Codes:**
  - `200 OK`: Binary file payload.
  - `404 Not Found`: Document not found, grant revoked, or user unauthorized.

### `POST /api/documents/{id}/versions`
- **Access:** Authenticated
- **Role:** Document Owner OR Grantee with `edit` level
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_EDIT)`
  - Full upload validation pipeline (size, magic bytes, zip-bomb guard).
  - Row lock on parent document (`FOR UPDATE`) to serialize version numbers.
  - In-memory encryption with AAD `document_id:version_id`.
- **Audit Event:** `DOCUMENT_VERSION_UPLOAD` (metadata: `{document_id, version_id, version_number}`)
- **Response Codes:**
  - `201 Created`: Version created.
  - `403 Forbidden`: User has `read` grant only.
  - `404 Not Found`: Document not found or access ungranted.

### `DELETE /api/documents/{id}`
- **Access:** Authenticated
- **Role:** Document Owner ONLY
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_DELETE)` (strictly requires `user.id == doc.owner_id`).
  - Sets `is_deleted = TRUE`, `deleted_at = NOW()`.
  - Automatically cancels any pending ownership transfer (`pending_owner_id = NULL`).
- **Audit Event:** `DOCUMENT_DELETE` (metadata: `{document_id}`)
- **Response Codes:**
  - `200 OK`: Document soft-deleted.
  - `403 Forbidden`: Grantee attempting to delete.
  - `404 Not Found`: User has no grant or document nonexistent.

### `POST /api/documents/{id}/restore`
- **Access:** Authenticated
- **Role:** Document Owner ONLY
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_RESTORE)` (strictly requires `user.id == doc.owner_id`).
  - Sets `is_deleted = FALSE`, `deleted_at = NULL`. Prior unrevoked, unexpired grants become active again.
- **Audit Event:** `DOCUMENT_RESTORE` (metadata: `{document_id}`)
- **Response Codes:**
  - `200 OK`: Document restored.
  - `404 Not Found`: Document not found or user is not owner.

---

## 3. Grants & Two-Step Ownership Transfers

### `GET /api/documents/{id}/grants`
- **Access:** Authenticated
- **Role:** Document Owner ONLY
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_ACCESS_LIST)`
  - Returns active and revoked grants with grantee UUIDs, levels, and expiration dates.
- **Audit Event:** `DOCUMENT_ACCESS_LIST_VIEW` (metadata: `{document_id}`)
- **Response Codes:**
  - `200 OK`: List of grants.
  - `403 Forbidden`: Grantee attempting to view access list.
  - `404 Not Found`: User has no access.

### `POST /api/documents/{id}/grants`
- **Access:** Authenticated
- **Role:** Document Owner ONLY
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_GRANT)`
  - Exact-match email lookup: resolves `grantee_email` to `grantee_user_id`.
  - Validates grantee exists and is active.
  - Level must be `read` or `edit`.
  - Optional `expires_at` must use DB clock check (`expires_at > NOW()`).
  - Prevents owner from granting to self.
  - Rate-limited per owner (DB counter) to prevent user enumeration.
- **Audit Event:** `PERMISSION_GRANT` (metadata: `{document_id, grantee_user_id, level}`)
- **Response Codes:**
  - `201 Created`: Grant created.
  - `400 Bad Request`: Self-grant or invalid parameter.
  - `403 Forbidden`: Non-owner attempting to grant.
  - `404 Not Found`: Target user not found (or document not found).
  - `429 Too Many Requests`: Grant creation rate limit exceeded.

### `POST /api/documents/{id}/grants/{grant_id}/revoke`
- **Access:** Authenticated
- **Role:** Document Owner ONLY
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_REVOKE)`
  - Sets `grant.revoked_at = NOW()`.
- **Audit Event:** `PERMISSION_REVOKE` (metadata: `{document_id, grant_id, grantee_user_id}`)
- **Response Codes:**
  - `200 OK`: Grant revoked.
  - `403 Forbidden`: Non-owner attempting to revoke.
  - `404 Not Found`: Grant or document not found.

### `POST /api/documents/{id}/transfer-request`
- **Access:** Authenticated
- **Role:** Document Owner ONLY
- **Server Checks:**
  - `authorize(user, doc, Action.DOCUMENT_TRANSFER)`
  - Exact-match email lookup for target recipient user.
  - Target recipient must have system role `owner` (`role == 'owner'`). Cannot transfer to `viewer`.
  - Sets `document.pending_owner_id = target_user_id`.
  - Original owner retains full control while pending.
- **Audit Event:** `OWNERSHIP_TRANSFER_REQUESTED` (metadata: `{document_id, target_user_id}`)
- **Response Codes:**
  - `200 OK`: Transfer requested.
  - `400 Bad Request`: Recipient does not possess system role `owner`.
  - `403 Forbidden`: Non-owner attempting transfer.
  - `404 Not Found`: Target user or document not found.

### `GET /api/documents/pending-transfers`
- **Access:** Authenticated
- **Role:** System `owner`
- **Server Checks:**
  - Returns pending transfer requests where `pending_owner_id == current_user.id`.
  - Returns **only** document ID, category, and transferring owner's username. Zero content, versions, or files are accessible.
- **Response Codes:**
  - `200 OK`: List of pending transfers.

### `POST /api/documents/{id}/transfer-accept`
- **Access:** Authenticated
- **Role:** Target Recipient (`user.id == doc.pending_owner_id`)
- **Server Checks:**
  - Validates `user.id == doc.pending_owner_id`.
  - Validates recipient account is active and document is not deleted.
  - Atomically sets `doc.owner_id = doc.pending_owner_id` and `doc.pending_owner_id = NULL`.
  - Old owner retains **nothing** unless re-granted by new owner.
  - Grants previously issued by old owner **remain in effect** on the document.
  - Revokes any existing grant the recipient previously held.
- **Audit Event:** `OWNERSHIP_TRANSFER_ACCEPTED` (metadata: `{document_id, previous_owner_id, new_owner_id}`)
- **Response Codes:**
  - `200 OK`: Ownership accepted.
  - `400 Bad Request`: Recipient disabled or document deleted.
  - `403 Forbidden`: User is not the designated pending recipient.
  - `404 Not Found`: Document not found.

### `POST /api/documents/{id}/transfer-reject`
- **Access:** Authenticated
- **Role:** Target Recipient (`user.id == doc.pending_owner_id`)
- **Server Checks:**
  - Sets `doc.pending_owner_id = NULL`.
- **Audit Event:** `OWNERSHIP_TRANSFER_REJECTED` (metadata: `{document_id, rejected_by_user_id}`)
- **Response Codes:**
  - `200 OK`: Transfer rejected.
  - `403 Forbidden`: Not pending recipient.

### `POST /api/documents/{id}/transfer-cancel`
- **Access:** Authenticated
- **Role:** Document Owner ONLY
- **Server Checks:**
  - Resets `doc.pending_owner_id = NULL`.
- **Audit Event:** `OWNERSHIP_TRANSFER_CANCELLED` (metadata: `{document_id}`)
- **Response Codes:**
  - `200 OK`: Transfer request cancelled.
  - `403 Forbidden`: Not document owner.

---

## 4. Administration & System Audit

### `POST /api/admin/users/{id}/trigger-reset`
- **Access:** Authenticated
- **Role:** `admin` ONLY
- **Server Checks:**
  - Validates target user exists.
  - Generates single-use 15-minute reset token in `password_reset_tokens`.
  - Dispatches reset link to user's registered email. Admin cannot view or set password directly. Admin cannot change user email.
- **Audit Event:** `ADMIN_PASSWORD_RESET_TRIGGERED` (metadata: `{target_user_id}`)
- **Response Codes:**
  - `200 OK`: Reset email dispatched.
  - `403 Forbidden`: Non-admin.
  - `404 Not Found`: Target user not found.

### `POST /api/admin/users/{id}/role`
- **Access:** Authenticated
- **Role:** `admin` ONLY
- **Server Checks:**
  - Updates `users.role` (`admin`, `owner`, `viewer`).
  - Increments `users.security_version` to immediately invalidate all existing sessions.
- **Audit Event:** `ADMIN_ROLE_CHANGED` (metadata: `{target_user_id, old_role, new_role}`)
- **Response Codes:**
  - `200 OK`: Role updated.
  - `403 Forbidden`: Non-admin.
  - `404 Not Found`: Target user not found.

### `POST /api/admin/users/{id}/status`
- **Access:** Authenticated
- **Role:** `admin` ONLY
- **Server Checks:**
  - Updates `users.is_active` (`True` or `False`).
  - Increments `users.security_version` to immediately invalidate all existing sessions.
- **Audit Event:** `ADMIN_USER_STATUS_CHANGED` (metadata: `{target_user_id, is_active}`)
- **Response Codes:**
  - `200 OK`: Status updated.
  - `403 Forbidden`: Non-admin.
  - `404 Not Found`: Target user not found.

### `GET /api/admin/audit`
- **Access:** Authenticated
- **Role:** `admin` ONLY
- **Server Checks:**
  - Viewing the audit log is itself audited.
  - Paginated audit log records with sequence numbers, actor UUIDs, actions, and refusal reasons.
- **Audit Event:** `AUDIT_LOG_VIEW` (metadata: `{page, limit}`)
- **Response Codes:**
  - `200 OK`: Audit records.
  - `403 Forbidden`: Non-admin.

### `POST /api/admin/audit/verify`
- **Access:** Authenticated
- **Role:** `admin` ONLY
- **Server Checks:**
  - Walks HMAC-SHA256 hash chain sequentially from genesis to current sequence number using `AUDIT_HMAC_KEY`.
  - Reports `VALID` or reports sequence number of first broken link.
- **Audit Event:** `AUDIT_CHAIN_VERIFY` (metadata: `{status}`)
- **Response Codes:**
  - `200 OK`: `{"status": "VALID", "total_records": 1042, "last_hash": "..."}` or `{"status": "CORRUPTED", "broken_sequence": 42}`.
  - `403 Forbidden`: Non-admin.

### `GET /api/admin/dashboard`
- **Access:** Authenticated
- **Role:** `admin` ONLY
- **Server Checks:**
  - Aggregates "worth noticing" events: multiple refused attempts by a user/IP, role changes, admin-triggered resets, failed audit verifications.
- **Audit Event:** `ADMIN_DASHBOARD_VIEW` (metadata: `{}`)
- **Response Codes:**
  - `200 OK`: Dashboard metrics.
  - `403 Forbidden`: Non-admin.
