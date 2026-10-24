from fastapi import FastAPI
from src.main import app
from tests.routes_util import all_api_routes, unprotected_routes

from scripts.route_inventory import PUBLIC  # single source of truth, shared with the API reference generator

def _openapi_ops():
    return {(m.upper(), p) for p, ms in app.openapi()["paths"].items() for m in ms}

def test_inventory_sees_every_route():
    """Guards against the checker silently skipping routes (it once saw 1 of 32)."""
    seen = {(m, r.path) for r in all_api_routes(app) for m in r.methods - {"HEAD"}}
    assert len(seen) >= 30
    assert _openapi_ops() <= seen | {("GET", "/")}, _openapi_ops() - seen

def test_every_route_requires_auth_or_is_explicitly_public():
    assert unprotected_routes(app, PUBLIC) == []

def test_public_list_has_no_stale_entries():
    seen = {(m, r.path) for r in all_api_routes(app) for m in r.methods - {"HEAD"}}
    assert PUBLIC <= seen, PUBLIC - seen

def test_the_checker_itself_can_fail():
    """Negative control: an unauthenticated route on a toy app MUST be flagged."""
    toy = FastAPI()
    @toy.get("/leak")
    async def leak(): return {}
    assert unprotected_routes(toy, set()) == [("GET", "/leak")]
