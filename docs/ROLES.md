# TrustVault: Role-Based & Document-Level Access Control Model (Revised Phase 1)

## 1. Principles of Authorisation

TrustVault implements a dual-layer authorisation model enforcing **Least Privilege**, **Complete Mediation**, and **Deny by Default**:

1. **Deny by Default:** Unless an explicit, positive rule grants a subject permission to perform an action on an object, access is categorically denied (`REFUSED`).
2. **Separation of System Duties vs. Data Access:** Administrative capabilities (user lifecycle management, role assignment, audit observation) do **not** confer content access rights. System administrators cannot read, search, or download document payloads unless an explicit document-level grant is issued to them by the document owner. Every administrative action and every document access attempt (permitted or refused) is permanently recorded in the immutable audit log.
3. **No Direct Admin Credential Overrides:** Administrators have **no capability** to directly set or override another user's password. They can only disable an account or trigger a single-use, time-limited password reset link dispatched to the user's verified email.
4. **Flat, Non-Inherited Document Grants:** Folder hierarchies or category tags are purely organisational labels. They **never** propagate, inherit, or cascade access permissions. This eliminates "confused deputy" and cascading disclosure vulnerabilities where gaining access to a parent container unintentionally exposes dozens or hundreds of nested documents.
5. **Single Source of Truth (`authorize()`):** No endpoint, router, background task, or service performs bespoke or ad-hoc permission evaluations. All access decisions converge into a single, centralized kernel function: `authorize(actor, resource, action, context)`.

---

## 2. Actors & System Roles

TrustVault recognizes three mutually distinct **System Roles** assigned to user accounts (`users.role`):

| System Role | Description | Core Capabilities | Inherent Data Access |
| :--- | :--- | :--- | :--- |
| **`admin`** | Security and platform compliance administrator. | Manage user lifecycles (disable, enable), assign system roles, trigger user password resets, view system-wide audit logs, monitor suspicious activity dashboards, verify cryptographic audit HMAC hash-chain integrity. | **NONE.** Cannot read, preview, download, or search document contents without an explicit grant. |
| **`owner`** | Standard platform creator and document publisher. | Upload new documents, create new document versions, assign and revoke per-document grants, initiate two-step ownership transfers, soft-delete and restore owned documents, inspect document-specific audit history. | Full ownership rights over their **own** documents. Zero rights over others' documents unless explicitly granted. |
| **`viewer`** | Restricted consumer account. | Access metadata and stream downloads for documents explicitly granted to them. If granted with `edit` privilege, may upload new versions of granted documents. | **NONE** by default. Strictly bounded to active, unrevoked grants. Cannot upload new root documents, cannot grant access to others. |

---

## 3. Document-Level Relationships & Grant Levels

Beyond system roles, authorisation for any document operation evaluates the direct relational bond between the actor and the target document:

### 3.1 Document Owner (`document.owner_id == actor.id`)
- Has sovereign authority over the document record and underlying ciphertext files.
- Can view metadata, download payloads, upload new versions, edit document metadata (title, category label).
- Can issue per-document grants (`read` or `edit`) to named user accounts via exact email lookup.
- Can instantly revoke grants.
- Can initiate a two-step ownership transfer (`transfer-request`). Ownership does not transfer until the designated recipient calls `transfer-accept`.
- Can soft-delete and restore their document. (Prior unrevoked, unexpired grants are preserved and re-activated upon restore).
- Can request AI grantee suggestions (with human-in-the-loop confirmation required).

### 3.2 Grantee Levels (`document_grants`)
Grants are strictly explicit tuples: `(document_id, grantee_user_id, level, granted_by, granted_at, expires_at, revoked_at)`.

- **`read`**:
  - View document metadata.
  - Download decrypted document file payload.
  - Search visibility (document appears in search results and facet counts).
  - *Restricted:* Cannot upload new versions, cannot grant access to others, cannot edit metadata, cannot soft-delete, cannot view audit history.
- **`edit`**:
  - All capabilities of `read`.
  - Can upload new document versions (under parent row lock `FOR UPDATE`).
  - *Restricted:* Cannot grant or revoke access, cannot transfer ownership, cannot soft-delete or restore, cannot change document category or title.

---

## 4. Comprehensive Capability Matrix

The following matrix documents the exact evaluation rules enforced in `authorize()`:

| Action / Capability | `viewer` (No Grant) | `viewer` (Grant: Read) | `viewer` (Grant: Edit) | `owner` (Other's Doc) | Document `owner` (Self) | `admin` (No Grant) | `admin` (Grant: Read) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Enable / Disable Users** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Assign / Change Roles** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Trigger User Password Reset**| ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Directly Set User Password**| ❌ | ❌ | ❌ | ❌ | ❌ | ❌ (Forbidden) | ❌ (Forbidden) |
| **View System Audit Log** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Verify Audit Hash Chain**| ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Upload New Document** | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Search Document** | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **View Document Metadata**| ❌ (404) | ✅ | ✅ | ❌ (404) | ✅ | ❌ (404) | ✅ |
| **Download Decrypted Payload**| ❌ (404) | ✅ | ✅ | ❌ (404) | ✅ | ❌ (404) | ✅ |
| **Upload New Version** | ❌ (404) | ❌ (403) | ✅ | ❌ (404) | ✅ | ❌ (404) | ❌ (403) |
| **Grant / Revoke Access** | ❌ (404) | ❌ (403) | ❌ (403) | ❌ (404) | ✅ | ❌ (404) | ❌ (403) |
| **Initiate Ownership Transfer**| ❌ (404) | ❌ (403) | ❌ (403) | ❌ (404) | ✅ | ❌ (404) | ❌ (403) |
| **Accept Ownership Transfer**| ❌ (403)* | ❌ (403)* | ❌ (403)* | ❌ (403)* | ❌ | ❌ (403)* | ❌ (403)* |
| **Soft-Delete Document** | ❌ (404) | ❌ (403) | ❌ (403) | ❌ (404) | ✅ | ❌ (404) | ❌ (403) |
| **Restore Deleted Document**| ❌ (404) | ❌ (404) | ❌ (404) | ❌ (404) | ✅ | ❌ (404) | ❌ (404) |
| **View Document Audit Log**| ❌ (404) | ❌ (403) | ❌ (403) | ❌ (404) | ✅ | ✅ (System Audit)| ✅ |
| **AI Grantee Suggestions** | ❌ (404) | ❌ (403) | ❌ (403) | ❌ (404) | ✅ | ❌ (404) | ❌ (403) |

*\* Note: Accepting an ownership transfer returns `200 OK` exclusively for the designated `pending_owner_id`. Any other user calling `transfer-accept` receives `403 Forbidden`.*

> **Security Note on Consistent Response Codes (403 vs 404):**
> - When an actor attempts an action on a document for which they possess **no grant** or ownership (or when the document does not exist), TrustVault returns **`404 Not Found`** (`{"detail": "Document not found"}`). This eliminates existence oracles.
> - When an actor has an existing valid relationship (e.g. `read` grant) but attempts an action exceeding their level (e.g. uploading a version), the system returns **`403 Forbidden`** because existence is already established.
