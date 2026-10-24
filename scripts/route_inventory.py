"""Single source for 'which routes exist and which are public'. FastAPI >= 0.146 hides included routers behind
_IncludedRouter, so they are flattened here (a checker that sees 1 of 32 routes proves nothing)."""
from fastapi.routing import APIRoute

# The ONLY routes that may be reachable without a session. Adding one here is a deliberate, reviewed act.
PUBLIC = {("GET", "/"), ("GET", "/healthz"), ("POST", "/api/auth/register"), ("POST", "/api/auth/login"),
          ("POST", "/api/auth/forgot-password"), ("POST", "/api/auth/reset-password"),
          ("POST", "/api/auth/email-change-confirm")}

def all_api_routes(app):
    for r in app.routes:
        if isinstance(r, APIRoute):
            yield r
        elif type(r).__name__ == "_IncludedRouter":
            yield from (x for x in r.original_router.routes if isinstance(x, APIRoute))

def _deps(dependant):
    for d in dependant.dependencies:
        yield d.call
        yield from _deps(d)

def has_auth(route) -> bool:
    return any("current_auth" in getattr(c, "__qualname__", "") or "require_role" in getattr(c, "__qualname__", "")
               for c in _deps(route.dependant))

def unprotected_routes(app, public: set):
    bad = []
    for r in all_api_routes(app):
        for m in sorted(r.methods - {"HEAD"}):
            if (m, r.path) not in public and not has_auth(r):
                bad.append((m, r.path))
    return bad
