# TrustVault Prompts & Engineering Decision Log

This log tracks prompts, tool suggestions, critical evaluations, deviations, and engineering rationale across the phases of TrustVault development.

---

## Log Entries

### Entry 1: Phase 1 - Architecture & Threat Model Design
- **Date:** 2026-10-18
- **Prompt:** User request to initiate Phase 1 of TrustVault: data model, `authorize()` design, audit trail integrity, instant revocation design, and `THREATS.md`.
- **Tool / LLM Initial Tendencies:**
  - Standard LLMs frequently default to stateless JWTs with local storage or cookies, claiming "JWTs are standard for REST APIs."
  - Standard architectures often implement hierarchical folder permissions (inherit down from `/FolderA`).
  - Standard error handling uses `403 Forbidden` whenever authorization fails on an existing ID.
- **What Was Wrong With That:**
  1. Stateless JWTs cannot achieve 0ms instant revocation without a stateful server-side blocklist, defeating their stateless nature. When a grant is revoked, a user with a valid JWT could continue downloading documents for minutes.
  2. Folder inheritance creates catastrophic over-permissioning ("see one file, now see forty") and complicates atomic revocation.
  3. Returning `403 Forbidden` for ungranted documents creates an IDOR existence oracle: an attacker guessing UUIDs knows a document exists when they get a 403 instead of a 404.
- **What We Did Instead:**
  1. Selected **server-side revocable sessions** backed by PostgreSQL, paired with httpOnly, Secure, SameSite=Strict cookies and double-submit CSRF headers. Instant revocation is 100% deterministic (0 ms).
  2. Implemented **flat per-document grants** with zero inheritance. Folders/categories are strictly metadata labels for search filtering.
  3. Enforced **existence concealment**: `authorize()` returns an identical `404 Not Found` for nonexistent documents and ungranted documents.
  4. Designed an append-only audit trail with PostgreSQL role grant restrictions (`REVOKE UPDATE, DELETE`), an immutable trigger, and a cryptographic SHA-256 hash chain with anchor row locking.
- **Git Commit:** 8cbea44

### Entry 2: Phase 1 Revision - Hardening Architecture, Audit, Revocation & Admin Scope
- **Date:** 2026-10-18
- **Prompt:** User feedback on Phase 1: remove chunk streaming in favor of full in-memory decryption with pre-send re-check; bind ciphertext using AAD; upgrade audit chain to HMAC-SHA256 with key outside DB; add periodic external anchoring; separate DB migration role from runtime app role; take anchor lock as late as possible before commit; isolate refusal logging from main session locks; remove admin direct password setting; enforce two-step ownership transfer; remove invented timing numbers; rate-limit refusals; adopt exact-match email lookup for grants; remove download tokens; use DB clock for grants; enforce session rotation + idle/absolute timeouts; preserve unrevoked grants on document restore; unify 403 vs 404 rules.
- **Critical Evaluation:**
  1. *Downloads:* Chunk-boundary checks added unnecessary streaming complexity and could still leave buffered packets in flight. With a 25MB cap, decrypting fully in memory, verifying the GCM tag, and re-checking `authorize()` immediately before response dispatch provides a clean guarantee: *no new bytes after revocation commits*. Binding AAD to `document_id:version_id` prevents ciphertext transplantation.
  2. *Audit:* Plain SHA-256 could theoretically be forged by a DB superuser if they altered historical records and recomputed the hashes. Upgrading to HMAC-SHA256 with an external key (`AUDIT_HMAC_KEY`) held strictly in the app environment stops a DB superuser from forging valid hashes. External anchoring seals historical integrity.
  3. *Audit Locking:* Locking the anchor at the very end of the transaction minimizes lock hold time to microseconds. Aborting/rolling back the primary request before invoking refusal logging guarantees that refusal transactions never deadlock with the request that triggered them.
  4. *Admin:* Removing direct password setting closes a major privilege abuse vector. Two-step ownership transfer eliminates malicious/unsolicited document dumping.
  5. *Existence & Rate Limiting:* Removing invented timing numbers and enforcing refusal rate limiting closes audit table flooding attacks.
- **What We Did:** Updated `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/ROLES.md`, and `THREATS.md`.
- **Git Commit:** 219327d

