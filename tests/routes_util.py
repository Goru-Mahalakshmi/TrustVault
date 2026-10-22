from fastapi.routing import APIRoute

def all_api_routes(app):
    """FastAPI >= 0.146 hides included routers behind _IncludedRouter; flatten them so nothing is skipped."""
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
    """(METHOD, path) of every route with neither an auth dependency nor an explicit public marker."""
    bad = []
    for r in all_api_routes(app):
        for m in sorted(r.methods - {"HEAD"}):
            if (m, r.path) not in public and not has_auth(r):
                bad.append((m, r.path))
    return bad
