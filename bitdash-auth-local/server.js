const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'bitdash-local-dev-secret-change-me';
const CODE_TTL_MIN = 15;

const db = new Database('./bitdash.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS verify_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS portfolios (
  user_id INTEGER PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true,
}));

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function issueAuth(res, user) {
  const token = jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('bitdash_token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function auth(req, res, next) {
  const token = req.cookies.bitdash_token;
  if (!token) return res.status(401).json({ ok: false, error: 'not_authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: 'invalid_token' });
  }
}

function genCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/auth/register', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ ok: false, error: 'invalid_input' });
  }

  const hash = await bcrypt.hash(password, 10);
  const existing = db.prepare('SELECT id, verified FROM users WHERE email = ?').get(email);

  if (!existing) {
    db.prepare('INSERT INTO users (email, password_hash, verified) VALUES (?, ?, 0)').run(email, hash);
  } else {
    db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(hash, email);
  }

  const code = genCode();
  db.prepare('UPDATE verify_codes SET used = 1 WHERE email = ? AND used = 0').run(email);
  db.prepare("INSERT INTO verify_codes (email, code, expires_at, used) VALUES (?, ?, datetime('now', ?), 0)")
    .run(email, code, `+${CODE_TTL_MIN} minutes`);

  // Modo local de teste: devolve código na resposta
  return res.json({ ok: true, message: 'verification_code_generated', devCode: code, ttlMinutes: CODE_TTL_MIN });
});

app.post('/auth/verify', (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || '').trim();
  if (!email || !code) return res.status(400).json({ ok: false, error: 'invalid_input' });

  const row = db.prepare(`
    SELECT * FROM verify_codes
    WHERE email = ? AND code = ? AND used = 0 AND expires_at > datetime('now')
    ORDER BY id DESC LIMIT 1
  `).get(email, code);

  if (!row) return res.status(400).json({ ok: false, error: 'invalid_or_expired_code' });

  db.prepare('UPDATE verify_codes SET used = 1 WHERE id = ?').run(row.id);
  db.prepare('UPDATE users SET verified = 1 WHERE email = ?').run(email);

  return res.json({ ok: true, message: 'email_verified' });
});

app.post('/auth/login', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  if (!user.verified) return res.status(403).json({ ok: false, error: 'email_not_verified' });

  const okPass = await bcrypt.compare(password, user.password_hash);
  if (!okPass) return res.status(401).json({ ok: false, error: 'invalid_credentials' });

  issueAuth(res, user);
  return res.json({ ok: true, user: { email: user.email } });
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie('bitdash_token');
  res.json({ ok: true });
});

app.get('/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT email FROM users WHERE id = ?').get(req.user.uid);
  if (!user) return res.status(401).json({ ok: false, error: 'user_not_found' });
  res.json({ ok: true, user });
});

app.post('/auth/change-password', auth, async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  if (newPassword.length < 6) return res.status(400).json({ ok: false, error: 'new_password_too_short' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.uid);
  if (!user) return res.status(404).json({ ok: false, error: 'user_not_found' });

  const okPass = await bcrypt.compare(currentPassword, user.password_hash);
  if (!okPass) return res.status(401).json({ ok: false, error: 'invalid_current_password' });

  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  res.json({ ok: true });
});

app.get('/portfolio', auth, (req, res) => {
  const row = db.prepare('SELECT data_json FROM portfolios WHERE user_id = ?').get(req.user.uid);
  if (!row) return res.json({ ok: true, portfolio: [] });
  try {
    return res.json({ ok: true, portfolio: JSON.parse(row.data_json) });
  } catch {
    return res.json({ ok: true, portfolio: [] });
  }
});

app.post('/portfolio', auth, (req, res) => {
  const portfolio = Array.isArray(req.body.portfolio) ? req.body.portfolio : null;
  if (!portfolio) return res.status(400).json({ ok: false, error: 'invalid_portfolio' });

  const data_json = JSON.stringify(portfolio);
  db.prepare(`
    INSERT INTO portfolios (user_id, data_json, updated_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET data_json = excluded.data_json, updated_at = datetime('now')
  `).run(req.user.uid, data_json);

  res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[bitdash-auth-local] running on http://0.0.0.0:${PORT}`);
});