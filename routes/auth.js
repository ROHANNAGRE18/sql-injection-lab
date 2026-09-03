/**
 * routes/auth.js
 *
 * Authentication routes for the SQL Injection Security Lab.
 *
 * Two endpoints are exposed:
 *
 *   POST /login-vulnerable  — INTENTIONALLY VULNERABLE: uses raw string
 *                             concatenation so SQL Injection can be demonstrated.
 *
 *   POST /login-secure      — SECURE: uses a parameterized query (prepared
 *                             statement) so the same payload is treated as
 *                             literal data and cannot modify the SQL structure.
 *
 * ⚠️  The vulnerable endpoint exists solely for controlled local education.
 *     Never write production code this way.
 */

const express = require("express");
const router  = express.Router();
const { db }  = require("../database/database");

// ---------------------------------------------------------------------------
// Helper — sanitise input length only (no escaping — that would defeat the demo)
// ---------------------------------------------------------------------------
function readField(value) {
  // Accept the raw string but cap length to prevent absurd payloads crashing the UI
  return typeof value === "string" ? value.slice(0, 300) : "";
}

// ---------------------------------------------------------------------------
// POST /login-vulnerable
// INTENTIONALLY VULNERABLE — FOR EDUCATIONAL USE ONLY
//
// User input is directly concatenated into the SQL string.
// A classic payload like:   ' OR '1'='1
// breaks out of the string literal and adds a tautology, making the WHERE
// clause always true → every row matches → first row returned → bypass.
// ---------------------------------------------------------------------------
router.post("/login-vulnerable", (req, res) => {
  const username = readField(req.body.username);
  const password = readField(req.body.password);

  // INTENTIONALLY VULNERABLE:
  // User input is directly concatenated into the SQL query.
  // This exists only to demonstrate SQL Injection in a local lab.
  // NEVER do this in production code.
  const query =
    `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(query, (err, row) => {
    if (err) {
      // Return the error message so the UI can surface it — intentional for the lab
      return res.status(400).json({
        success:      false,
        injected:     true,
        message:      `Database error: ${err.message}`,
        query,
        username:     null,
        role:         null,
      });
    }

    if (row) {
      // A row was returned — either legitimate login or successful injection
      const isInjection = detectInjection(username, password);
      return res.json({
        success:   true,
        injected:  isInjection,
        message:   isInjection
          ? "SQL Injection successful — authentication logic bypassed!"
          : "Valid credentials — login successful.",
        query,
        username:  row.username,
        role:      row.role,
      });
    }

    // No row matched — login denied
    return res.status(401).json({
      success:  false,
      injected: false,
      message:  "Invalid credentials — no matching record found.",
      query,
      username: null,
      role:     null,
    });
  });
});

// ---------------------------------------------------------------------------
// POST /login-secure
// SECURE IMPLEMENTATION — parameterized query / prepared statement
//
// The ? placeholders are bound to the input values by the SQLite driver.
// The driver serialises them as data — never as executable SQL syntax.
// Injecting ' OR '1'='1 will literally search for a username equal to that
// whole string, which does not exist → login denied.
// ---------------------------------------------------------------------------
router.post("/login-secure", (req, res) => {
  const username = readField(req.body.username);
  const password = readField(req.body.password);

  // SECURE: parameterized query — input is bound as data, not SQL syntax.
  // The database driver handles escaping internally; the query structure
  // is fixed at compile time and cannot be modified by user input.
  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;

  db.get(query, [username, password], (err, row) => {
    if (err) {
      return res.status(500).json({
        success:  false,
        blocked:  false,
        message:  `Database error: ${err.message}`,
        query,
        params:   [username, password],
        username: null,
        role:     null,
      });
    }

    if (row) {
      return res.json({
        success:  true,
        blocked:  false,
        message:  "Valid credentials — login successful.",
        query,
        params:   [username, password],
        username: row.username,
        role:     row.role,
      });
    }

    // Injection payload was treated as a literal string — no match
    const wasInjectionAttempt = detectInjection(username, password);
    return res.status(401).json({
      success:  false,
      blocked:  wasInjectionAttempt,
      message:  wasInjectionAttempt
        ? "SQL Injection blocked — payload treated as literal data, no matching user found."
        : "Invalid credentials — login denied.",
      query,
      params:   [username, password],
      username: null,
      role:     null,
    });
  });
});

// ---------------------------------------------------------------------------
// detectInjection — simple heuristic to flag obvious injection payloads
// Used only for educational UI labelling, not for any security decision.
// ---------------------------------------------------------------------------
function detectInjection(username, password) {
  const sqlPatterns = [
    /'\s*or\s*/i,
    /'\s*and\s*/i,
    /--/,
    /\/\*/,
    /;\s*drop/i,
    /;\s*select/i,
    /union\s+select/i,
    /1\s*=\s*1/,
    /1\s*=\s*0/,
  ];
  const combined = `${username} ${password}`;
  return sqlPatterns.some((re) => re.test(combined));
}

module.exports = router;
