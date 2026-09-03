# SQL Injection Security Lab

A local, interactive cybersecurity lab that demonstrates how SQL Injection works and how parameterized queries prevent it — side by side, in your browser.

> ⚠️ **Educational use only.** This application intentionally contains a vulnerable endpoint for controlled local demonstration. Never use these techniques against systems without explicit written permission.

---

## Overview

SQL Injection is one of the most prevalent and dangerous web vulnerabilities, consistently appearing in the [OWASP Top 10](https://owasp.org/www-project-top-ten/). It occurs when user-supplied input is embedded directly into a SQL query, allowing an attacker to modify the query's structure and logic.

This lab provides a hands-on environment to:

- See exactly how a vulnerable string-concatenation query can be exploited
- Watch the injected SQL query structure change in real time
- Test the same payload against a secure parameterized query and observe it being blocked
- Understand the root cause and the correct fix through interactive comparison

---

## Features

- **Vulnerable authentication endpoint** — raw string concatenation, intentionally exploitable
- **Secure authentication endpoint** — parameterized query, injection-proof
- **Live SQL query preview** — updates as you type, showing how input modifies the query
- **Query visualization** — displays the exact SQL that was executed after each submission
- **Attack flow diagrams** — step-by-step visual walkthrough of both attack and defence paths
- **Payload cheatsheet** — click-to-fill common SQL injection payloads and valid credentials
- **Security comparison table** — direct feature-by-feature comparison
- **Learning section** — explains SQL Injection, bypass mechanics, prepared statements, and defence in depth
- **Modern cybersecurity UI** — dark theme, professional layout, portfolio-ready

---

## Technologies

| Layer    | Technology                      |
|----------|---------------------------------|
| Runtime  | Node.js                         |
| Server   | Express.js 5                    |
| Database | SQLite3 (in-memory)             |
| Frontend | HTML5, CSS3, Vanilla JavaScript |

No external frontend frameworks — pure HTML/CSS/JS for maximum clarity.

---

## Project Structure

```
sql-injection-demo/
│
├── public/
│   ├── index.html      # Full dashboard UI
│   ├── style.css       # Dark cybersecurity theme
│   └── script.js       # Frontend logic & query visualization
│
├── database/
│   └── database.js     # SQLite init, schema, sample users
│
├── routes/
│   └── auth.js         # /login-vulnerable and /login-secure endpoints
│
├── server.js           # Express app entry point
├── package.json
├── package-lock.json
├── .gitignore
└── README.md
```

---

## Installation

**Prerequisites:** Node.js 18 or later.

```bash
# 1. Clone or download the project
git clone https://github.com/ROHANNAGRE18/sql-injection-lab.git
cd sql-injection-demo

# 2. Install dependencies
npm install

# 3. Start the server
node server.js
```

Then open your browser at:

```
http://localhost:3000
```

The in-memory database is seeded automatically on every startup — no database setup required.

---

## Lab Demonstration

The lab ships with three fake accounts (local use only):

| Username | Password       | Role          |
|----------|----------------|---------------|
| admin    | Admin@Lab123   | administrator |
| alice    | Alice@Pass456  | user          |
| bob      | Bob@Pass789    | user          |

### Step-by-step test scenarios

**1. Normal valid login (both panels)**
- Username: `admin`
- Password: `Admin@Lab123`
- Expected: both panels grant access ✅

**2. Wrong password (both panels)**
- Username: `admin`
- Password: `wrongpassword`
- Expected: both panels deny access 🔒

**3. SQL Injection — authentication bypass (vulnerable panel)**
- Username: `' OR 1=1--`
- Password: *(leave blank)*
- Expected on `/login-vulnerable`: 🚨 **Access granted without valid credentials**
- The `--` comments out the password check entirely; `OR 1=1` is always true → first row returned

**4. Same payload against secure panel**
- Username: `' OR 1=1--`
- Password: *(leave blank)*
- Expected on `/login-secure`: 🛡️ **Attack blocked**
- The payload is bound as a literal string; the database searches for a username equal to `' OR 1=1--` — no match found

**5. Comment-based bypass (vulnerable panel only)**
- Username: `admin'--`
- Password: *(leave blank)*
- The `--` comments out the rest of the query, removing the password check entirely

Use the **Payload Cheatsheet** on the page to fill values with a single click.

---

## Security Concepts

### SQL Injection
Occurs when user input is concatenated directly into a SQL string. Special characters — particularly the single quote `'` — can escape the string context and inject arbitrary SQL syntax.

### Authentication Bypass
A boolean injection such as `' OR '1'='1` appends a condition that is always true to the WHERE clause. Every row in the table matches, so the database returns the first user regardless of the supplied password.

### String Concatenation (the problem)
```js
// UNSAFE — never do this
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```
The input `' OR '1'='1` transforms this into:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''
```

### Parameterized Queries (the solution)
```js
// SAFE — always prefer this
const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
db.get(query, [username, password], callback);
```
The `?` placeholders are filled in by the database driver *after* the query is compiled. User input cannot alter the query structure.

### Defense in Depth
Parameterized queries are the primary defence against SQL Injection. Additional recommended controls:

- **Input validation** — enforce expected formats and lengths
- **Least-privilege DB accounts** — the app DB user should only have SELECT/INSERT/UPDATE on necessary tables
- **Password hashing** — use bcrypt or Argon2; never store plain-text passwords
- **Structured error handling** — never expose raw database error messages to users
- **Logging and monitoring** — detect and alert on anomalous query patterns
- **Regular security testing** — SAST, DAST, and manual penetration testing

---

## Learning Outcomes

After completing this lab you should be able to:

- Explain what SQL Injection is and why it occurs
- Identify unsafe string concatenation patterns in code
- Demonstrate an authentication bypass using a boolean injection payload
- Explain why parameterized queries prevent SQL Injection at a fundamental level
- List additional defensive controls beyond parameterized queries
- Articulate the difference between treating input as code versus treating it as data

---

## Disclaimer

This application **intentionally contains a SQL Injection vulnerability** for controlled cybersecurity education.

- Run it locally or in an isolated, authorized lab environment only
- Do not expose this application on a public network or production server
- Never apply these techniques against systems without explicit written permission
- The credentials used are entirely fake and are not connected to any real service

Unauthorized access to computer systems is illegal. This lab exists solely to help developers understand and prevent vulnerabilities.
