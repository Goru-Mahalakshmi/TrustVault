"""Generate docs/API_REFERENCE.md FROM THE CODE: every route, who may call it (derived from its dependencies and the
authorize() action it uses), rate limiting, CSRF requirement and the audit events it writes. A test fails if the
committed file is stale, so this document cannot describe an endpoint that does not exist.
    python -m scripts.gen_api_reference"""
import inspect, pathlib, re
from src.main import app
from scripts.route_inventory import PUBLIC, all_api_routes, has_auth

OWNER = "Document owner only"
WHO = {"READ": "Document owner, or a grantee with an active `read` or `edit` grant",
       "DOWNLOAD": "Document owner, or a grantee with an active `read` or `edit` grant",
       "EDIT": "Document owner, or a grantee with an active `edit` grant",
       "TRANSFER_ACCEPT": "The designated pending recipient only", "TRANSFER_REJECT": "The designated pending recipient only"}
FAIL = {"READ": "No relationship: `404`", "DOWNLOAD": "No relationship: `404`", "EDIT": "No relationship: `404`; read-only grantee: `403`",
        "TRANSFER_ACCEPT": "Everyone else: `404`", "TRANSFER_REJECT": "Everyone else: `404`"}
OWNER_FAIL = "Grantee: `403`; everyone else (admins included): `404`"
SECTIONS = [("Authentication", "/api/auth"), ("Documents", "/api/documents"), ("Administration", "/api/admin"), ("System", "/")]

def describe(route, method):
    src = inspect.getsource(route.endpoint)
    action = re.search(r"Action\.(\w+)", src)
    notes = []
    if (method, route.path) in PUBLIC:
        who = "Anyone (no session)"
    elif route.path.startswith("/api/admin"):
        who = "Admin (system role `admin`)"
    elif action:
        a = action.group(1)
        who = WHO.get(a, OWNER)
        notes.append("Others: " + FAIL.get(a, OWNER_FAIL))
    elif 'ctx.role != "owner"' in src:
        who = "Signed-in user with system role `owner`"
    else:
        who = "Any signed-in user"
        if route.path in ("/api/documents", "/api/documents/trash", "/api/documents/pending-transfers"):
            notes.append("Returns only the caller's own / granted items")
    if method in ("POST", "PUT", "PATCH", "DELETE") and has_auth(route):
        notes.append("needs `X-CSRF-Token`")
    if "enforce_rate_limit(" in src:
        notes.append("rate-limited")
    events = sorted(set(re.findall(r'audit\(db, ctx, request, "(\w+)"', src)) | set(re.findall(r'"(AI_SUGGESTION_\w+)"', src)))
    refusals = "refusals audited" if (action or 'ctx.role != "owner"' in src) else ""
    if refusals:
        notes.append(refusals)
    summary = (inspect.getdoc(route.endpoint) or route.name.replace("_", " ")).splitlines()[0]
    return who, "; ".join(notes), ", ".join(f"`{e}`" for e in events) or "-", summary

def render() -> str:
    rows = {}
    for r in all_api_routes(app):
        for m in sorted(r.methods - {"HEAD"}):
            rows[(m, r.path)] = (r, m)
    out = ["# API reference (generated)", "",
           "Generated from the code by `python -m scripts.gen_api_reference`; a test fails if it is stale. All JSON. Authentication is a",
           "session cookie (`tv_session`, HttpOnly, Secure, SameSite=Strict); state-changing calls also need the `X-CSRF-Token` header returned by",
           "login or `GET /api/auth/me`. Errors: `401` not signed in, `403` CSRF/insufficient privilege, `404 {\"detail\": \"Document not found\"}`",
           "for anything you may not see or that does not exist (identical on purpose), `422` invalid input, `429` rate limit (`Retry-After`).", ""]
    done = set()
    for title, prefix in SECTIONS:
        group = [k for k in sorted(rows, key=lambda k: (k[1], k[0])) if k not in done and (k[1].startswith(prefix) if prefix != "/" else True)]
        if not group:
            continue
        out += [f"## {title}", "", "| Method | Path | Who may call it | What happens to others / notes | Audit events written |", "|---|---|---|---|---|"]
        for k in group:
            done.add(k)
            who, notes, events, summary = describe(*rows[k])
            out.append(f"| {k[0]} | `{k[1]}` | {who} | {summary}. {notes} | {events} |".replace(". . ", ". "))
        out.append("")
    return "\n".join(out) + "\n"

if __name__ == "__main__":
    pathlib.Path("docs/API_REFERENCE.md").write_text(render(), encoding="utf-8")
    print("docs/API_REFERENCE.md written")
