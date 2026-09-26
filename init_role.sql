-- Initialisation rôle et base
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mcp_intruder') THEN
        CREATE ROLE mcp_intruder WITH LOGIN SUPERUSER;
    END IF;
END $$;
