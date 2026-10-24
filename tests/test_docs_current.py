"""Documentation that cannot silently drift from the code."""
import pathlib, re
import pytest
from scripts import export_schema, gen_api_reference
from scripts.route_inventory import PUBLIC, all_api_routes
from src.main import app

ROOT = pathlib.Path(__file__).resolve().parent.parent

def test_api_reference_is_current():
    assert (ROOT / "docs/API_REFERENCE.md").read_text(encoding="utf-8") == gen_api_reference.render(), \
        "docs/API_REFERENCE.md is stale: run python -m scripts.gen_api_reference"

def test_api_reference_names_every_route_and_who_may_call_it():
    text = (ROOT / "docs/API_REFERENCE.md").read_text(encoding="utf-8")
    for r in all_api_routes(app):
        for m in r.methods - {"HEAD"}:
            line = next((l for l in text.splitlines() if l.startswith(f"| {m} | `{r.path}` |")), None)
            assert line, (m, r.path)
            assert ("Anyone" in line) == ((m, r.path) in PUBLIC), f"public marking disagrees for {m} {r.path}"

def test_schema_sql_is_current():
    assert (ROOT / "db/schema.sql").read_text(encoding="utf-8") == export_schema.render(), \
        "db/schema.sql is stale: run python -m scripts.export_schema"

def _tests_cited(doc: str):
    cited, last_file = [], None
    for m in re.finditer(r"(tests/[\w/]+\.py)?::(test_\w+)|(tests/[\w/]+\.py)", doc):
        if m.group(3):
            cited.append((m.group(3), None)); last_file = m.group(3)
        else:
            f = m.group(1) or last_file
            last_file = f
            cited.append((f, m.group(2)))
    return cited

@pytest.mark.parametrize("doc", ["THREATS.md", "README.md", "DEPLOY.md"])
def test_every_test_and_file_cited_in_the_docs_exists(doc):
    path = ROOT / doc
    if not path.exists():
        pytest.skip(f"{doc} not present")
    text = path.read_text(encoding="utf-8")
    missing = []
    for f, name in _tests_cited(text):
        if not f or not (ROOT / f).exists():
            missing.append((f, name)); continue
        if name and not re.search(rf"def {re.escape(name)}\b", (ROOT / f).read_text(encoding="utf-8")):
            missing.append((f, name))
    for token in set(re.findall(r"`((?:scripts|src|db|docker|deploy|docs)/[\w./-]+\.\w+)`", text)):
        if not (ROOT / token).exists():
            missing.append((token, None))
    assert not missing, f"{doc} cites things that do not exist: {missing}"
