# AI Context & Defensive Principles for TrustVault

This document provides reusable operational guidelines, security invariants, and coding constraints for any AI model or engineer working on the TrustVault platform.

## 1. Prime Directive: Fail-Closed Authorisation

1. **No Ad-Hoc Permissions:** Never write inline authorization logic inside route handlers (e.g. `if user.id == doc.owner_id:` inside a controller). All checks must invoke the central `authorize()` service function or declarative FastAPI security dependencies.
2. **Deny by Default:** If an unhandled exception or unexpected state occurs during permission evaluation, access is immediately denied.
3. **Existence Concealment:** If an authenticated or unauthenticated user queries an object they do not possess permissions to see, always return `404 Not Found` with the generic body `{"detail": "Document not found"}`. Never return `403 Forbidden` for an ungranted object, as doing so reveals that the ID exists.
4. **Separation of Admin from Content:** System administrators (`role == 'admin'`) manage platform governance, accounts, and audit observation. They have zero inherent access to document files or contents. An admin attempting to read a document without an explicit grant must be denied and audited.

## 2. Audit Trail Invariants

1. **Every Refusal is Audited:** Refused access attempts are as important as permitted ones. When access is denied, the denial must be committed to the database in an isolated transaction so that it persists even when the request fails.
2. **Transaction Coupling for Mutations:** When a document, grant, or user is mutated, the corresponding audit log entry must be committed in the exact same database transaction. An operation cannot succeed without its audit record.
3. **No Secrets in Logs:** Never write passwords, master keys, session tokens, CSRF tokens, or file payload contents to audit logs or application logs.
4. **Append-Only & Cryptographic Chaining:** Audit rows must never be updated or deleted. Each row's `row_hash` must be calculated from `prev_hash` and the canonical representation of the row payload.

## 3. Storage & Cryptography Invariants

1. **No Files in Web Root:** Uploaded files must never be stored inside web roots, public directories, or served via static file mounts.
2. **Random Storage Names:** Storage paths must always be decoupled from user filenames (`{document_uuid}_{version_uuid}.enc`).
3. **Envelope Encryption at Rest:** Every file is encrypted using an ephemeral 256-bit AES-GCM data encryption key (DEK). The DEK is encrypted using the master key from the environment.
4. **Attachment Only Downloads:** Downloads must always specify `Content-Disposition: attachment; filename="<sanitized>"`, `X-Content-Type-Options: nosniff`, and a restrictive `Content-Security-Policy`.

## 4. AI Feature Constraints

1. **Advisory Only:** The AI suggestion endpoint may only suggest potential grantees and explain its reasoning. It is strictly prohibited from mutating database records, creating grants, or changing user roles.
2. **Human in the Loop:** A human document owner must explicitly confirm each grant via the standard grant endpoint.
3. **Untrusted Model Output:** All output from the model must be strictly validated. User IDs returned by the model must be checked for existence in the database before being presented.
4. **Zero Content Exposure:** The model must never receive document file contents. Only non-sensitive metadata (title, category) may be passed to the model.
