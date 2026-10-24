# API reference (generated)

Generated from the code by `python -m scripts.gen_api_reference`; a test fails if it is stale. All JSON. Authentication is a
session cookie (`tv_session`, HttpOnly, Secure, SameSite=Strict); state-changing calls also need the `X-CSRF-Token` header returned by
login or `GET /api/auth/me`. Errors: `401` not signed in, `403` CSRF/insufficient privilege, `404 {"detail": "Document not found"}`
for anything you may not see or that does not exist (identical on purpose), `422` invalid input, `429` rate limit (`Retry-After`).

## Authentication

| Method | Path | Who may call it | What happens to others / notes | Audit events written |
|---|---|---|---|---|
| POST | `/api/auth/change-password` | Any signed-in user | change password. needs `X-CSRF-Token` | - |
| POST | `/api/auth/email-change-confirm` | Anyone (no session) | email change confirm. rate-limited | - |
| POST | `/api/auth/email-change-request` | Any signed-in user | email change request. needs `X-CSRF-Token` | - |
| POST | `/api/auth/forgot-password` | Anyone (no session) | forgot password. rate-limited | - |
| POST | `/api/auth/login` | Anyone (no session) | login. rate-limited | - |
| POST | `/api/auth/logout` | Any signed-in user | logout. needs `X-CSRF-Token` | - |
| GET | `/api/auth/me` | Any signed-in user | me.  | - |
| POST | `/api/auth/register` | Anyone (no session) | register. rate-limited | - |
| POST | `/api/auth/reset-password` | Anyone (no session) | reset password. rate-limited | - |

## Documents

| Method | Path | Who may call it | What happens to others / notes | Audit events written |
|---|---|---|---|---|
| GET | `/api/documents` | Any signed-in user | Search runs ONLY over documents the caller may read: the permission predicate is part of every query. Returns only the caller's own / granted items | `SEARCH_QUERY` |
| POST | `/api/documents` | Signed-in user with system role `owner` | upload document. needs `X-CSRF-Token`; rate-limited; refusals audited | `DOCUMENT_UPLOAD` |
| GET | `/api/documents/pending-transfers` | Signed-in user with system role `owner` | pending transfers. refusals audited | - |
| GET | `/api/documents/trash` | Any signed-in user | Your OWN soft-deleted documents (the only way to find an id to restore). Never anyone else's.. Returns only the caller's own / granted items | - |
| DELETE | `/api/documents/{doc_id}` | Document owner only | delete document. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; refusals audited | `DOCUMENT_DELETE` |
| GET | `/api/documents/{doc_id}` | Document owner, or a grantee with an active `read` or `edit` grant | get document. Others: No relationship: `404`; refusals audited | `DOCUMENT_VIEW` |
| PATCH | `/api/documents/{doc_id}` | Document owner only | update document. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; refusals audited | `DOCUMENT_METADATA_UPDATE` |
| GET | `/api/documents/{doc_id}/audit` | Document owner only | Who touched THIS document and when, including refused attempts. Owner only; the view is itself audited.. Others: Grantee: `403`; everyone else (admins included): `404`; refusals audited | `DOCUMENT_AUDIT_VIEW` |
| GET | `/api/documents/{doc_id}/download` | Document owner, or a grantee with an active `read` or `edit` grant | download document. Others: No relationship: `404`; refusals audited | - |
| POST | `/api/documents/{doc_id}/grantee-suggestions` | Document owner only | grantee suggestions. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; refusals audited | `AI_GRANTEE_SUGGESTION`, `AI_SUGGESTED_GRANTEE` |
| POST | `/api/documents/{doc_id}/grantee-suggestions/{suggestion_id}/decisions` | Document owner only | The ONLY way a suggestion can lead to access: the owner, with a session + CSRF token, decides per person.. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; rate-limited; refusals audited | `AI_SUGGESTION_ACCEPTED`, `AI_SUGGESTION_MODIFIED`, `AI_SUGGESTION_REJECTED` |
| GET | `/api/documents/{doc_id}/grants` | Document owner only | list grants. Others: Grantee: `403`; everyone else (admins included): `404`; refusals audited | `DOCUMENT_ACCESS_LIST_VIEW` |
| POST | `/api/documents/{doc_id}/grants` | Document owner only | create grant. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; rate-limited; refusals audited | `PERMISSION_GRANT_FAILED` |
| POST | `/api/documents/{doc_id}/grants/{grant_id}/revoke` | Document owner only | revoke grant. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; refusals audited | `PERMISSION_REVOKE` |
| POST | `/api/documents/{doc_id}/restore` | Document owner only | restore document. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; refusals audited | `DOCUMENT_RESTORE` |
| POST | `/api/documents/{doc_id}/transfer-accept` | The designated pending recipient only | transfer accept. Others: Everyone else: `404`; needs `X-CSRF-Token`; refusals audited | `OWNERSHIP_TRANSFER_ACCEPTED` |
| POST | `/api/documents/{doc_id}/transfer-cancel` | Document owner only | transfer cancel. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; refusals audited | `OWNERSHIP_TRANSFER_CANCELLED` |
| POST | `/api/documents/{doc_id}/transfer-reject` | The designated pending recipient only | transfer reject. Others: Everyone else: `404`; needs `X-CSRF-Token`; refusals audited | `OWNERSHIP_TRANSFER_REJECTED` |
| POST | `/api/documents/{doc_id}/transfer-request` | Document owner only | transfer request. Others: Grantee: `403`; everyone else (admins included): `404`; needs `X-CSRF-Token`; rate-limited; refusals audited | `OWNERSHIP_TRANSFER_REQUESTED` |
| GET | `/api/documents/{doc_id}/versions` | Document owner, or a grantee with an active `read` or `edit` grant | list versions. Others: No relationship: `404`; refusals audited | `DOCUMENT_VERSIONS_VIEW` |
| POST | `/api/documents/{doc_id}/versions` | Document owner, or a grantee with an active `edit` grant | upload version. Others: No relationship: `404`; read-only grantee: `403`; needs `X-CSRF-Token`; rate-limited; refusals audited | `DOCUMENT_VERSION_UPLOAD` |
| GET | `/api/documents/{doc_id}/versions/{version_number}/download` | Document owner, or a grantee with an active `read` or `edit` grant | download version. Others: No relationship: `404`; refusals audited | - |

## Administration

| Method | Path | Who may call it | What happens to others / notes | Audit events written |
|---|---|---|---|---|
| GET | `/api/admin/audit` | Admin (system role `admin`) | Document activity and permission changes (ids only: admins never see titles, filenames or contents)..  | `AUDIT_LOG_VIEW` |
| POST | `/api/admin/audit/verify` | Admin (system role `admin`) | verify chain. needs `X-CSRF-Token` | `AUDIT_CHAIN_VERIFY` |
| GET | `/api/admin/dashboard` | Admin (system role `admin`) | dashboard.  | `ADMIN_DASHBOARD_VIEW` |
| GET | `/api/admin/users` | Admin (system role `admin`) | list users.  | - |
| POST | `/api/admin/users/{user_id}/role` | Admin (system role `admin`) | change role. needs `X-CSRF-Token` | `ADMIN_ROLE_CHANGED` |
| POST | `/api/admin/users/{user_id}/status` | Admin (system role `admin`) | set status. needs `X-CSRF-Token` | `ADMIN_USER_STATUS_CHANGED` |
| POST | `/api/admin/users/{user_id}/trigger-reset` | Admin (system role `admin`) | trigger reset. needs `X-CSRF-Token` | `ADMIN_PASSWORD_RESET_TRIGGERED` |

## System

| Method | Path | Who may call it | What happens to others / notes | Audit events written |
|---|---|---|---|---|
| GET | `/` | Anyone (no session) | index.  | - |
| GET | `/healthz` | Anyone (no session) | healthz.  | - |
