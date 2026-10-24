#!/bin/sh
# Single-container start for hosts like Render: create/upgrade the schema, optionally seed, then serve.
# On such hosts there is ONE database user, so it plays both roles (see THREATS.md, 'Knowingly accepted').
set -e
export OWNER_DATABASE_URL="${OWNER_DATABASE_URL:-$DATABASE_URL}"
python -m scripts.init_db
if [ "${SEED_ON_START:-0}" = "1" ]; then python -m scripts.seed; fi
exec uvicorn src.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers "${WEB_CONCURRENCY:-1}" --no-server-header
