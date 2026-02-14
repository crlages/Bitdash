const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'bitdash-local-dev-secret-change-me';
const CODE_TTL_MIN = 15;

const dbPath = path.join(__dirname, '..', 'bitdash.db');
const db = new Database(dbPath);
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

function parseBrNum(str) {
  return Number(String(str || '').replace(/\./g, '').replace(',', '.'));
}

async function fetchText(url, timeoutMs = 12000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (!r.ok) throw new Error(`http_${r.status}`);
    return await r.text();
  } finally {
    clearTimeout(t);
  }
}

function matchNum(txt, patterns) {
  for (const p of patterns) {
    const m = txt.match(p);
    if (m) return parseBrNum(m[1]);
  }
  return null;
}

app.get('/market/asset', async (req, res) => {
  try {
    const tickerRaw = String(req.query.ticker || '').trim().toUpperCase();
    const clsRaw = String(req.query.cls || '').trim().toUpperCase();
    const ticker = tickerRaw === 'BITCOIN' ? 'BTC' : tickerRaw;
    const cls = clsRaw || (ticker.endsWith('11') ? 'FII' : 'ACAO');

    const CRYPTO_MAP = { BTC:'bitcoin', ETH:'ethereum', SOL:'solana', XRP:'ripple', BNB:'binancecoin', ADA:'cardano', DOGE:'dogecoin', LTC:'litecoin', USDT:'tether' };

    // FX
    let usdBrl = 5.2;
    try {
      const fxTxt = await fetchText('https://economia.awesomeapi.com.br/json/last/USD-BRL');
      const fx = JSON.parse(fxTxt);
      const bid = Number(fx?.USDBRL?.bid);
      if (Number.isFinite(bid) && bid > 0) usdBrl = bid;
    } catch {}

    if (cls === 'CRIPTO') {
      const id = CRYPTO_MAP[ticker];
      if (!id) return res.status(400).json({ ok:false, error:'crypto_not_mapped' });
      const j = JSON.parse(await fetchText(`https://api.coingecko.com/api/v3/simple/price?ids=${id}&vs_currencies=usd&include_24hr_change=true`));
      const usd = Number(j?.[id]?.usd);
      const ch = Number(j?.[id]?.usd_24h_change);
      if (!Number.isFinite(usd)) return res.status(502).json({ ok:false, error:'crypto_price_not_found' });
      return res.json({ ok:true, ticker, cls:'CRIPTO', priceBrl: usd * usdBrl, metric: Number.isFinite(ch) ? ch : null, metricType:'chg24h', usdBrl });
    }

    const lower = ticker.toLowerCase();
    const sources = cls === 'FII'
      ? [
          `https://r.jina.ai/http://investidor10.com.br/fiis/${lower}/`,
          `https://r.jina.ai/http://statusinvest.com.br/fundos-imobiliarios/${lower}`,
          `https://r.jina.ai/http://www.fundsexplorer.com.br/funds/${ticker}`,
        ]
      : (cls === 'ETF EUA' || cls === 'ETF_EUA')
        ? [
            `https://r.jina.ai/http://investidor10.com.br/etfs-global/${lower}/`,
            `https://r.jina.ai/http://statusinvest.com.br/etf/eua/${lower}`,
          ]
        : [
            `https://r.jina.ai/http://investidor10.com.br/acoes/${lower}/`,
            `https://r.jina.ai/http://statusinvest.com.br/acoes/${lower}`,
          ];

    let priceBrl = null;
    let pvp = null;

    for (const src of sources) {
      try {
        const txt = await fetchText(src);

        if (!Number.isFinite(pvp)) {
          pvp = matchNum(txt, [
            /P\/VP\s*([0-9\.]+,[0-9]+)/i,
            /P\/VP[^0-9]*([0-9\.]+,[0-9]+)/i,
          ]);
        }

        if (!Number.isFinite(priceBrl)) {
          priceBrl = matchNum(txt, [
            /Cotação\s*R\$\s*([0-9\.]+,[0-9]+)/i,
            /Valor atual\s*R\$\s*([0-9\.]+,[0-9]+)/i,
            /Preço\s*R\$\s*([0-9\.]+,[0-9]+)/i,
          ]);

          if (!Number.isFinite(priceBrl)) {
            const usd = matchNum(txt, [
              /Cotação\s*US\$\s*([0-9\.]+,[0-9]+)/i,
              /Valor atual\s*US\$\s*([0-9\.]+,[0-9]+)/i,
            ]);
            if (Number.isFinite(usd)) priceBrl = usd * usdBrl;
          }
        }

        if (Number.isFinite(priceBrl) && Number.isFinite(pvp)) break;
      } catch {
        // tenta próxima fonte
      }
    }

    const ov = PRICE_OVERRIDES[ticker];
    if (ov && (!Number.isFinite(priceBrl) || priceBrl < ov.min || priceBrl > ov.max)) {
      priceBrl = ov.fallback;
    }

    return res.json({ ok:true, ticker, cls, priceBrl: Number.isFinite(priceBrl) ? priceBrl : null, metric: Number.isFinite(pvp) ? pvp : null, metricType:'pvp', usdBrl });
  } catch (e) {
    return res.status(500).json({ ok:false, error:'market_fetch_failed', detail:String(e.message || e) });
  }
});

const newsCache = new Map();

const PRICE_OVERRIDES = {
  HGBS11: { min: 1, max: 80, fallback: 20.18 },
};

function decodeHtml(str='') {
  return String(str)
    .replace(/<!\[CDATA\[|\]\]>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

app.get('/market/news', async (req, res) => {
  try {
    const raw = String(req.query.tickers || '');
    const limit = Math.min(20, Math.max(1, Number(req.query.limit || 12)));
    const tickers = [...new Set(raw.split(',').map(t => t.trim().toUpperCase()).filter(Boolean))].slice(0, 12);

    if (!tickers.length) return res.json({ ok: true, news: [] });

    const cacheKey = `${tickers.join(',')}|${limit}`;
    const now = Date.now();
    const cached = newsCache.get(cacheKey);
    if (cached && now - cached.ts < 5 * 60 * 1000) {
      return res.json({ ok: true, news: cached.data, cached: true });
    }

    const out = [];

    for (const ticker of tickers) {
      const q = encodeURIComponent(`${ticker} mercado financeiro`);
      const url = `https://news.google.com/rss/search?q=${q}&hl=pt-BR&gl=BR&ceid=BR:pt-419`;

      try {
        const xml = await fetchText(url, 10000);
        const itemMatches = xml.match(/<item>[\s\S]*?<\/item>/g) || [];

        for (const item of itemMatches.slice(0, 4)) {
          const title = decodeHtml((item.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || '').trim();
          const link = decodeHtml((item.match(/<link>([\s\S]*?)<\/link>/i) || [])[1] || '').trim();
          const pubDate = decodeHtml((item.match(/<pubDate>([\s\S]*?)<\/pubDate>/i) || [])[1] || '').trim();
          const source = decodeHtml((item.match(/<source[^>]*>([\s\S]*?)<\/source>/i) || [])[1] || '').trim() || 'Google News';

          if (!title || !link) continue;
          out.push({ ticker, title, url: link, source, time: pubDate ? new Date(pubDate).toISOString() : null });
        }
      } catch {
        // segue para o próximo ticker
      }
    }

    const dedup = [];
    const seen = new Set();
    for (const n of out) {
      if (seen.has(n.url)) continue;
      seen.add(n.url);
      dedup.push(n);
    }

    dedup.sort((a, b) => (new Date(b.time || 0).getTime()) - (new Date(a.time || 0).getTime()));
    const data = dedup.slice(0, limit);

    newsCache.set(cacheKey, { ts: now, data });
    return res.json({ ok: true, news: data, cached: false });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'news_fetch_failed', detail: String(e.message || e) });
  }
});

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