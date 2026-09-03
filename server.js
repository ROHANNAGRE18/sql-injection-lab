/**
 * server.js — SQL Injection Security Lab
 *
 * Entry point. Responsibilities:
 *   1. Initialize the SQLite database with sample users.
 *   2. Mount the authentication routes (vulnerable + secure).
 *   3. Serve the static frontend from /public.
 *   4. Start the HTTP server.
 *
 * Usage:
 *   node server.js
 *   → Open http://localhost:3000
 */

'use strict';

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');

const { initializeDatabase } = require('./database/database');
const authRoutes             = require('./routes/auth');

// ─── App setup ───────────────────────────────────────────────────────────────

const app  = express();
const PORT = process.env.PORT || 3000;

// Parse JSON and URL-encoded request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (index.html, style.css, script.js) from /public
app.use(express.static(path.join(__dirname, 'public')));

// ─── Routes ──────────────────────────────────────────────────────────────────

// Authentication endpoints:
//   POST /login-vulnerable  — intentionally unsafe (string concatenation)
//   POST /login-secure      — safe (parameterized query)
app.use('/', authRoutes);

// Catch-all 404 for undefined API routes
app.use((req, res, next) => {
  // Only intercept non-static API paths
  if (req.path.startsWith('/login')) {
    return res.status(404).json({ error: 'Route not found.' });
  }
  next();
});

// ─── Global error handler ────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // Log internally but do not expose raw error details to the client
  console.error('[Server Error]', err.message);
  res.status(500).json({ error: 'An internal server error occurred.' });
});

// ─── Start ───────────────────────────────────────────────────────────────────

// Initialize DB first, then start listening
initializeDatabase();

app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║     SQL Injection Security Lab           ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
  console.log(`  🟢  Server running at  http://localhost:${PORT}`);
  console.log('');
  console.log('  Test accounts (fake credentials — lab only):');
  console.log('    admin / Admin@Lab123      (role: administrator)');
  console.log('    alice / Alice@Pass456     (role: user)');
  console.log('    bob   / Bob@Pass789       (role: user)');
  console.log('');
  console.log('  ⚠️  Educational lab — run locally only.');
  console.log('');
});
