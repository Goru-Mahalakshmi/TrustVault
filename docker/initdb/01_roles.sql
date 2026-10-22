-- Bootstrap (runs once as the Postgres superuser; superuser is NEVER used by the app or by tests).
CREATE ROLE trustvault_owner LOGIN PASSWORD 'owner_dev_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;  -- migrations / schema only
CREATE ROLE trustvault_app   LOGIN PASSWORD 'app_dev_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE;  -- what the API connects as
CREATE DATABASE trustvault_test OWNER trustvault_owner;
CREATE DATABASE trustvault      OWNER trustvault_owner;
