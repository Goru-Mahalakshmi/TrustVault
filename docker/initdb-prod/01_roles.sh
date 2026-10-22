#!/bin/sh
# Runs once, when the production database volume is first created. Passwords come from the environment
# (use hex only: python -c "import secrets;print(secrets.token_hex(24))").
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<EOSQL
CREATE ROLE trustvault_owner LOGIN PASSWORD '${OWNER_DB_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE trustvault_app   LOGIN PASSWORD '${APP_DB_PASSWORD}'   NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE trustvault OWNER trustvault_owner;
EOSQL
