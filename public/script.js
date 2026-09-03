/**
 * script.js — SQL Injection Security Lab
 *
 * Handles:
 *  - Vulnerable and secure login form submissions
 *  - Live query preview (shows the SQL that will be executed)
 *  - Result rendering with injection/blocked status
 *  - Syntax-highlighted query visualization
 *  - Payload cheatsheet copy-to-fill interactions
 */

'use strict';

// ─── DOM refs ──────────────────────────────────────────────────────────────

const vulnForm       = document.getElementById('vuln-form');
const vulnUser       = document.getElementById('vuln-username');
const vulnPass       = document.getElementById('vuln-password');
const vulnBtn        = document.getElementById('vuln-btn');
const vulnResult     = document.getElementById('vuln-result');
const vulnQueryBlock = document.getElementById('vuln-query-block');
const vulnQuerySql   = document.getElementById('vuln-query-sql');

const secureForm       = document.getElementById('secure-form');
const secureUser       = document.getElementById('secure-username');
const securePass       = document.getElementById('secure-password');
const secureBtn        = document.getElementById('secure-btn');
const secureResult     = document.getElementById('secure-result');
const secureQueryBlock = document.getElementById('secure-query-block');
const secureQuerySql   = document.getElementById('secure-query-sql');

// ─── Live query preview ────────────────────────────────────────────────────
// Update the static code snippet in the comparison section as the user types
// so they can see the injection happening in real time.

function updateVulnPreview() {
  const u = vulnUser.value || 'username';
  const p = vulnPass.value || 'password';
  const preview = document.getElementById('vuln-live-preview');
  if (!preview) return;

  const isInjection = looksLikeInjection(vulnUser.value, vulnPass.value);
  const uHtml = isInjection
    ? escHtml(u).replace(/('.*)/g, '<span class="sql-inj">$1</span>')
    : `<span class="sql-str">${escHtml(u)}</span>`;
  const pHtml = isInjection
    ? escHtml(p)
    : `<span class="sql-str">${escHtml(p)}</span>`;

  preview.innerHTML =
    `<span class="sql-kw">SELECT</span> * <span class="sql-kw">FROM</span> users\n` +
    `<span class="sql-kw">WHERE</span> username = '${uHtml}'\n` +
    `<span class="sql-kw">AND</span> password = '${pHtml}'`;
}

vulnUser.addEventListener('input', updateVulnPreview);
vulnPass.addEventListener('input', updateVulnPreview);

// ─── Form submit — vulnerable ──────────────────────────────────────────────

vulnForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  vulnBtn.disabled = true;
  vulnBtn.textContent = 'Testing…';
  vulnResult.className = 'result-box';
  vulnResult.style.display = 'none';

  const username = vulnUser.value.trim();
  const password = vulnPass.value;

  try {
    const res  = await fetch('/login-vulnerable', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();
    renderVulnResult(data, username, password);
  } catch (err) {
    renderNetworkError(vulnResult);
  } finally {
    vulnBtn.disabled = false;
    vulnBtn.innerHTML = '⚡ Test Vulnerable Login';
  }
});

// ─── Form submit — secure ─────────────────────────────────────────────────

secureForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  secureBtn.disabled = true;
  secureBtn.textContent = 'Testing…';
  secureResult.className = 'result-box';
  secureResult.style.display = 'none';

  const username = secureUser.value.trim();
  const password = securePass.value;

  try {
    const res  = await fetch('/login-secure', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();
    renderSecureResult(data, username, password);
  } catch (err) {
    renderNetworkError(secureResult);
  } finally {
    secureBtn.disabled = false;
    secureBtn.innerHTML = '🛡️ Test Secure Login';
  }
});

// ─── Render: vulnerable result ────────────────────────────────────────────

function renderVulnResult(data, username, password) {
  // ── Query visualization ──
  vulnQueryBlock.style.display = 'block';
  vulnQuerySql.innerHTML = highlightSql(data.query, true, username, password);

  // ── Status box ──
  let boxClass, icon, title, bodyHtml;

  if (data.success && data.injected) {
    // SQL injection successful
    boxClass = 'injected';
    icon     = '🚨';
    title    = 'SQL INJECTION SUCCESSFUL';
    bodyHtml = `
      ${infoRow('Status',   '<span class="ri-value danger">Authentication Bypassed</span>')}
      ${infoRow('User',     `<span class="ri-value highlight">${escHtml(data.username)}</span>`)}
      ${infoRow('Role',     `<span class="ri-value highlight">${escHtml(data.role)}</span>`)}
      ${infoRow('Payload',  `<span class="ri-value danger">${escHtml(username || '(empty)')}</span>`)}
      <div style="margin-top:12px;padding:10px 12px;background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);border-radius:6px;font-size:0.78rem;color:#fca5a5;line-height:1.6;">
        The <code>' OR '1'='1</code> payload broke out of the string literal and added a
        tautology (<code>OR '1'='1</code>) that is always true. The WHERE clause matched
        every row, so the first database user was returned — no valid password needed.
      </div>`;
  } else if (data.success && !data.injected) {
    // Legitimate login
    boxClass = 'login-ok';
    icon     = '✅';
    title    = 'Login Successful';
    bodyHtml = `
      ${infoRow('Status', '<span class="ri-value success">Valid Credentials</span>')}
      ${infoRow('User',   `<span class="ri-value highlight">${escHtml(data.username)}</span>`)}
      ${infoRow('Role',   `<span class="ri-value highlight">${escHtml(data.role)}</span>`)}`;
  } else if (!data.success && data.message && data.message.startsWith('Database error')) {
    // SQLi caused a syntax error (also educational)
    boxClass = 'error';
    icon     = '⚠️';
    title    = 'SQL Syntax Error (also from injection)';
    bodyHtml = `
      ${infoRow('Status',  '<span class="ri-value danger">Query Failed</span>')}
      ${infoRow('Error',   `<span class="ri-value danger">${escHtml(data.message)}</span>`)}
      <div style="margin-top:12px;padding:10px 12px;background:rgba(234,179,8,0.07);border:1px solid rgba(234,179,8,0.25);border-radius:6px;font-size:0.78rem;color:#fde68a;line-height:1.6;">
        Your payload caused a SQL syntax error — another form of SQL Injection impact.
        Real attackers refine payloads until they work; error messages also leak database details.
      </div>`;
  } else {
    // Normal login failure
    boxClass = 'login-fail';
    icon     = '🔒';
    title    = 'Access Denied';
    bodyHtml = `
      ${infoRow('Status',  '<span class="ri-value">Invalid Credentials</span>')}
      ${infoRow('Message', `<span class="ri-value">${escHtml(data.message)}</span>`)}
      <div style="margin-top:12px;font-size:0.78rem;color:var(--text-muted);">
        Try the payload: <code style="color:var(--yellow);">' OR 1=1--</code> in the username field with any password.
      </div>`;
  }

  vulnResult.className = `result-box ${boxClass} visible`;
  vulnResult.style.display = 'block';
  vulnResult.innerHTML = `
    <div class="result-box-header">
      <span>${icon}</span>
      <span>${title}</span>
    </div>
    <div class="result-box-body">${bodyHtml}</div>`;
}

// ─── Render: secure result ────────────────────────────────────────────────

function renderSecureResult(data, username, password) {
  // ── Query visualization ──
  secureQueryBlock.style.display = 'block';
  secureQuerySql.innerHTML =
    `<span class="sql-kw">SELECT</span> * <span class="sql-kw">FROM</span> users\n` +
    `<span class="sql-kw">WHERE</span> username = <span class="sql-param">?</span>\n` +
    `<span class="sql-kw">AND</span> password = <span class="sql-param">?</span>\n\n` +
    `<span style="color:var(--text-muted);font-style:italic;">-- Bound parameters (treated as data, never SQL):\n` +
    `-- [1] ${escHtml(username || '(empty)')}\n` +
    `-- [2] ${password ? '(password provided)' : '(empty)'}</span>`;

  // ── Status box ──
  let boxClass, icon, title, bodyHtml;

  if (data.success) {
    boxClass = 'login-ok';
    icon     = '✅';
    title    = 'Login Successful';
    bodyHtml = `
      ${infoRow('Status', '<span class="ri-value success">Valid Credentials</span>')}
      ${infoRow('User',   `<span class="ri-value highlight">${escHtml(data.username)}</span>`)}
      ${infoRow('Role',   `<span class="ri-value highlight">${escHtml(data.role)}</span>`)}`;
  } else if (data.blocked) {
    boxClass = 'blocked';
    icon     = '🛡️';
    title    = 'SQL INJECTION BLOCKED';
    bodyHtml = `
      ${infoRow('Status',  '<span class="ri-value success">Attack Prevented</span>')}
      ${infoRow('Payload', `<span class="ri-value danger">${escHtml(username || '(empty)')}</span>`)}
      <div style="margin-top:12px;padding:10px 12px;background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.2);border-radius:6px;font-size:0.78rem;color:#86efac;line-height:1.6;">
        The parameterized query bound your payload as a <strong>literal string value</strong>.
        The database searched for a username literally equal to <code>${escHtml(username)}</code>
        — which doesn't exist — so authentication failed. The SQL structure was never modified.
      </div>`;
  } else {
    boxClass = 'login-fail';
    icon     = '🔒';
    title    = 'Access Denied';
    bodyHtml = `
      ${infoRow('Status',  '<span class="ri-value">Invalid Credentials</span>')}
      ${infoRow('Message', `<span class="ri-value">${escHtml(data.message)}</span>`)}`;
  }

  secureResult.className = `result-box ${boxClass} visible`;
  secureResult.style.display = 'block';
  secureResult.innerHTML = `
    <div class="result-box-header">
      <span>${icon}</span>
      <span>${title}</span>
    </div>
    <div class="result-box-body">${bodyHtml}</div>`;
}

// ─── Network error fallback ───────────────────────────────────────────────

function renderNetworkError(container) {
  container.className = 'result-box error visible';
  container.style.display = 'block';
  container.innerHTML = `
    <div class="result-box-header"><span>⚠️</span><span>Connection Error</span></div>
    <div class="result-box-body">
      <p style="font-size:0.82rem;color:var(--text-secondary);">
        Could not reach the server. Make sure <code>node server.js</code> is running on port 3000.
      </p>
    </div>`;
}

// ─── SQL syntax highlighter ───────────────────────────────────────────────
// Highlights the actual executed query returned from the server,
// and marks injected portions in red.

function highlightSql(rawSql, isVulnerable, username, password) {
  if (!rawSql) return '';

  let html = escHtml(rawSql);

  // Keywords
  const keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'NULL', 'IS', 'LIKE', 'IN', 'UPDATE', 'INSERT', 'DROP', 'DELETE'];
  keywords.forEach(kw => {
    html = html.replace(new RegExp(`\\b${kw}\\b`, 'gi'), `<span class="sql-kw">${kw}</span>`);
  });

  // Highlight injected portion in red if this is a vulnerable query
  if (isVulnerable && looksLikeInjection(username, password)) {
    // Mark single-quoted strings that contain injection patterns
    html = html.replace(/'([^']*(?:OR|AND|--|\/\*|1=1)[^']*)'/gi,
      (match) => `<span class="sql-inj">${match}</span>`);
  } else {
    // Normal string literals in green
    html = html.replace(/'([^']*)'/g, `<span class="sql-str">'$1'</span>`);
  }

  return html;
}

// ─── Injection heuristic (mirrors server-side) ───────────────────────────

function looksLikeInjection(username, password) {
  const patterns = [/'\s*or\s*/i, /'\s*and\s*/i, /--/, /\/\*/, /1\s*=\s*1/i, /union\s+select/i];
  const combined = `${username || ''} ${password || ''}`;
  return patterns.some(re => re.test(combined));
}

// ─── HTML escape ──────────────────────────────────────────────────────────

function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── Info row helper ──────────────────────────────────────────────────────

function infoRow(label, valueHtml) {
  return `
    <div class="result-info-row">
      <span class="ri-label">${label}</span>
      <span class="ri-sep" style="color:var(--text-muted)">→</span>
      ${valueHtml}
    </div>`;
}

// ─── Payload cheatsheet: click to fill ───────────────────────────────────
// Clicking a payload value in the cheatsheet fills both panels' inputs.

document.querySelectorAll('[data-fill-user]').forEach(el => {
  el.addEventListener('click', () => {
    const u = el.getAttribute('data-fill-user');
    const p = el.getAttribute('data-fill-pass') || '';
    if (u !== null) {
      vulnUser.value   = u;
      secureUser.value = u;
    }
    if (p !== null) {
      vulnPass.value   = p;
      securePass.value = p;
    }
    updateVulnPreview();

    // Visual feedback
    el.style.background = 'rgba(0,212,255,0.15)';
    setTimeout(() => { el.style.background = ''; }, 600);

    // Scroll to lab section
    document.getElementById('lab-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

// ─── Init live preview on load ───────────────────────────────────────────
updateVulnPreview();
