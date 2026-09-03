/**
 * database.js
 *
 * Initializes an in-memory SQLite database with a sample users table.
 * Uses FAKE credentials — this is purely for local educational demonstration.
 *
 * Schema:
 *   users (id, username, password, role)
 *
 * Sample users:
 *   admin   | Admin@Lab123   | administrator
 *   alice   | Alice@Pass456  | user
 *   bob     | Bob@Pass789    | user
 */

const sqlite3 = require("sqlite3").verbose();

// In-memory database — resets on every server restart (intentional for this lab)
const db = new sqlite3.Database(":memory:", (err) => {
  if (err) {
    console.error("[DB] Failed to open in-memory database:", err.message);
    process.exit(1);
  }
  console.log("[DB] In-memory SQLite database initialized.");
});

/**
 * Creates the users table and inserts sample records.
 * Called once at server startup.
 */
function initializeDatabase() {
  db.serialize(() => {
    // Create users table with id, username, password, and role columns
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY,
        username TEXT    NOT NULL,
        password TEXT    NOT NULL,
        role     TEXT    NOT NULL DEFAULT 'user'
      )`,
      (err) => {
        if (err) {
          console.error("[DB] Error creating users table:", err.message);
          return;
        }
        console.log("[DB] Users table created.");
      }
    );

    // Insert sample users with fake credentials (educational use only)
    const users = [
      [1, "admin", "Admin@Lab123",  "administrator"],
      [2, "alice", "Alice@Pass456", "user"],
      [3, "bob",   "Bob@Pass789",   "user"],
    ];

    const stmt = db.prepare(
      "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)"
    );

    users.forEach(([id, username, password, role]) => {
      stmt.run(id, username, password, role, (err) => {
        if (err) {
          console.error(`[DB] Error inserting user '${username}':`, err.message);
        }
      });
    });

    stmt.finalize(() => {
      console.log("[DB] Sample users seeded: admin, alice, bob");
    });
  });
}

module.exports = { db, initializeDatabase };
