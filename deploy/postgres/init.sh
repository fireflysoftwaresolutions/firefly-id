#!/bin/bash
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  --set=db_password="$(cat /run/secrets/db-password)" <<'SQL'
CREATE ROLE firefly_id LOGIN PASSWORD :'db_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE firefly_id OWNER firefly_id;
REVOKE ALL ON DATABASE firefly_id FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE firefly_id TO firefly_id;
\connect firefly_id
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO firefly_id;
SQL
