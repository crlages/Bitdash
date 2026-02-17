export default {
  async fetch(request, env, ctx) {
    const C = (res) => cors(res, request);
    try {
      const url = new URL(request.url);

      if (request.method === 'OPTIONS') return C(new Response(null, { status: 204 }));

      if (url.pathname === '/health') {
        return C(json({ ok: true, runtime: 'cloudflare-worker' }));
      }

      if (url.pathname === '/auth/google' && request.method === 'POST') {
        return C(await authGoogle(request, env));
      }

      if (url.pathname === '/auth/me' && request.method === 'GET') {
        return C(await authMe(request, env));
      }

      if (url.pathname === '/auth/logout' && request.method === 'POST') {
        return C(await authLogout());
      }

      if (url.pathname === '/portfolio' && request.method === 'GET') {
        return C(await getPortfolio(request, env));
      }

      if (url.pathname === '/portfolio' && request.method === 'POST') {
        return C(await savePortfolio(request, env));
      }

      if (url.pathname === '/payments/status' && request.method === 'GET') {
        return C(await paymentStatus(request, env));
      }

      if (url.pathname === '/market/asset' && request.method === 'GET') {
        return C(await marketAsset(request));
      }

      if (url.pathname === '/market/news' && request.method === 'GET') {
        return C(await marketNews(request));
      }

      if (url.pathname === '/market/batch' && request.method === 'POST') {
        return C(await marketBatch(request));
      }

      if (url.pathname === '/payments/dev-approve' && request.method === 'POST') {
        return C(await paymentDevApprove(request, env));
      }

      if (url.pathname === '/payments/webhook' && request.method === 'POST') {
        return C(await paymentWebhook(request, env));
      }

      if (url.pathname === '/auth/request-access-code' && request.method === 'POST') {
        return C(await requestAccessCode(request, env));
      }

      if (url.pathname === '/auth/verify-access-code' && request.method === 'POST') {
        return C(await verifyAccessCode(request, env));
      }

      return C(json({ ok: false, error: 'not_found' }, 404));
    } catch (e) {
      return C(json({ ok: false, error: 'internal_error', detail: String(e.message || e) }, 500));
    }
  }
};

function cors(res, request = null) {
  const h = new Headers(res.headers);
  const reqOrigin = request?.headers?.get('Origin') || '';

  const isPagesOrigin = /^https:\/\/[a-z0-9-]+\.bitdash\.pages\.dev$/i.test(reqOrigin)
    || reqOrigin === 'https://bitdash.pages.dev';
  const isLocalOrigin = reqOrigin === 'http://localhost:8001' || reqOrigin === 'http://127.0.0.1:8001';
  const allowOrigin = (isPagesOrigin || isLocalOrigin) ? reqOrigin : 'https://bitdash.pages.dev';

  h.set('Access-Control-Allow-Origin', allowOrigin);
  h.set('Vary', 'Origin');
  h.set('Access-Control-Allow-Credentials', 'true');
  h.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  h.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  return new Response(res.body, { status: res.status, headers: h });
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers }
  });
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function b64urlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const base = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base.length % 4 ? '='.repeat(4 - (base.length % 4)) : '';
  return atob(base + pad);
}

async function hmacSign(input, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(input));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function createSessionCookie(payload, secret) {
  const body = b64urlEncode(JSON.stringify(payload));
  const sig = await hmacSign(body, secret);
  return `${body}.${sig}`;
}

async function parseSessionCookie(request, secret) {
  const raw = getCookie(request, 'bitdash_token');
  if (!raw) return null;
  const [body, sig] = raw.split('.');
  if (!body || !sig) return null;
  const expected = await hmacSign(body, secret);
  if (sig !== expected) return null;

  try {
    const payload = JSON.parse(b64urlDecode(body));
    if (!payload?.email || !payload?.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const pairs = cookie.split(/;\s*/).map(x => x.split('='));
  const found = pairs.find(([k]) => k === name);
  return found ? decodeURIComponent(found[1] || '') : null;
}

function setAuthCookie(token) {
  return `bitdash_token=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 7}`;
}

function clearAuthCookie() {
  return 'bitdash_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}

async function authGoogle(request, env) {
  const body = await request.json();
  const credential = String(body?.credential || '').trim();
  if (!credential) return json({ ok: false, error: 'missing_google_credential' }, 400);

  const verify = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
  if (!verify.ok) return json({ ok: false, error: 'google_token_invalid' }, 401);
  const g = await verify.json();

  if (!g?.email || String(g.email_verified) !== 'true') {
    return json({ ok: false, error: 'google_email_not_verified' }, 401);
  }
  if (env.GOOGLE_CLIENT_ID && g.aud !== env.GOOGLE_CLIENT_ID) {
    return json({ ok: false, error: 'google_audience_mismatch' }, 401);
  }

  const email = normalizeEmail(g.email);
  await env.DB.prepare(`
    INSERT INTO users (email, verified, created_at)
    VALUES (?, 1, datetime('now'))
    ON CONFLICT(email) DO UPDATE SET verified = 1
  `).bind(email).run();

  const sub = await env.DB.prepare('SELECT status FROM subscriptions WHERE email = ?').bind(email).first();
  const premium = sub?.status === 'approved';

  const token = await createSessionCookie({
    email,
    name: g.name || null,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  }, env.JWT_SECRET);

  return json({
    ok: true,
    user: { email, name: g.name || null, picture: g.picture || null },
    premium,
    premiumStatus: sub?.status || 'pending'
  }, 200, { 'Set-Cookie': setAuthCookie(token) });
}

async function authMe(request, env) {
  const session = await parseSessionCookie(request, env.JWT_SECRET);
  if (!session) return json({ ok: false, error: 'not_authenticated' }, 401);
  const sub = await env.DB.prepare('SELECT status FROM subscriptions WHERE email = ?').bind(session.email).first();
  return json({ ok: true, user: { email: session.email, name: session.name || null }, premium: sub?.status === 'approved', premiumStatus: sub?.status || 'pending' });
}

async function authLogout() {
  return json({ ok: true }, 200, { 'Set-Cookie': clearAuthCookie() });
}

async function getPortfolio(request, env) {
  const session = await parseSessionCookie(request, env.JWT_SECRET);
  if (!session) return json({ ok: false, error: 'not_authenticated' }, 401);

  const row = await env.DB.prepare('SELECT data_json FROM portfolios WHERE email = ?').bind(session.email).first();
  return json({ ok: true, portfolio: row?.data_json ? JSON.parse(row.data_json) : [] });
}

async function savePortfolio(request, env) {
  const session = await parseSessionCookie(request, env.JWT_SECRET);
  if (!session) return json({ ok: false, error: 'not_authenticated' }, 401);

  const body = await request.json();
  if (!Array.isArray(body?.portfolio)) return json({ ok: false, error: 'invalid_portfolio' }, 400);

  await env.DB.prepare(`
    INSERT INTO portfolios (email, data_json, updated_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(email) DO UPDATE SET data_json = excluded.data_json, updated_at = datetime('now')
  `).bind(session.email, JSON.stringify(body.portfolio)).run();

  return json({ ok: true });
}

function normalizeSubStatus(status = '') {
  const v = String(status).toLowerCase();
  if (['approved', 'authorized', 'active', 'paid'].includes(v)) return 'approved';
  if (['cancelled', 'canceled', 'rejected', 'refunded', 'paused'].includes(v)) return 'rejected';
  return 'pending';
}

async function paymentStatus(request, env) {
  const url = new URL(request.url);
  const email = normalizeEmail(url.searchParams.get('email'));
  if (!email) return json({ ok: false, error: 'email_required' }, 400);

  const row = await env.DB.prepare('SELECT status FROM subscriptions WHERE email = ?').bind(email).first();
  return json({ ok: true, email, status: row?.status || 'pending' });
}

async function paymentDevApprove(request, env) {
  const body = await request.json();
  const email = normalizeEmail(body?.email);
  if (!email) return json({ ok: false, error: 'email_required' }, 400);

  await env.DB.prepare(`
    INSERT INTO subscriptions (email, status, provider, provider_ref, created_at, updated_at)
    VALUES (?, 'approved', 'mercadopago', ?, datetime('now'), datetime('now'))
    ON CONFLICT(email) DO UPDATE SET status='approved', updated_at=datetime('now')
  `).bind(email, `dev-${Date.now()}`).run();

  return json({ ok: true, email, status: 'approved' });
}

async function paymentWebhook(request, env) {
  const body = await request.json();
  const email = normalizeEmail(
    body.email || body.payer_email || body.payer?.email || body.data?.payer_email || body.metadata?.email || ''
  );
  const status = normalizeSubStatus(body.status || body.data?.status || body.subscription_status || 'pending');
  const providerRef = String(body.id || body.data?.id || body.preapproval_id || body.subscription_id || '').trim() || null;

  if (!email) return json({ ok: true, ignored: true, reason: 'missing_email' });

  await env.DB.prepare(`
    INSERT INTO subscriptions (email, status, provider, provider_ref, created_at, updated_at)
    VALUES (?, ?, 'mercadopago', ?, datetime('now'), datetime('now'))
    ON CONFLICT(email) DO UPDATE SET status=excluded.status, provider_ref=COALESCE(excluded.provider_ref,subscriptions.provider_ref), updated_at=datetime('now')
  `).bind(email, status, providerRef).run();

  return json({ ok: true });
}

async function requestAccessCode(request, env) {
  const body = await request.json();
  const email = normalizeEmail(body?.email);
  if (!email) return json({ ok: false, error: 'email_required' }, 400);

  const sub = await env.DB.prepare('SELECT status FROM subscriptions WHERE email = ?').bind(email).first();
  if (sub?.status !== 'approved') return json({ ok: false, error: 'payment_not_approved' }, 403);

  const code = String(Math.floor(100000 + Math.random() * 900000));
  await env.DB.prepare('UPDATE access_codes SET used = 1 WHERE email = ? AND used = 0').bind(email).run();
  await env.DB.prepare("INSERT INTO access_codes (email, code, expires_at, used, created_at) VALUES (?, ?, datetime('now', '+15 minutes'), 0, datetime('now'))")
    .bind(email, code).run();

  if (env.RESEND_API_KEY) {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: env.RESEND_FROM || 'Bitdash <onboarding@resend.dev>',
        to: [email],
        subject: 'Bitdash - Sua contra senha',
        html: `<p>Pagamento confirmado.</p><p><strong>Contra senha:</strong> ${code}</p><p>Expira em 15 minutos.</p>`
      })
    });

    if (!r.ok) {
      const t = await r.text();
      return json({ ok: false, error: 'email_send_failed', detail: t.slice(0, 200) }, 500);
    }

    return json({ ok: true, ttlMinutes: 15, emailMode: 'resend' });
  }

  return json({ ok: true, ttlMinutes: 15, emailMode: 'dev', devCode: code });
}

async function verifyAccessCode(request, env) {
  const body = await request.json();
  const email = normalizeEmail(body?.email);
  const code = String(body?.code || '').trim();
  if (!email || !code) return json({ ok: false, error: 'invalid_input' }, 400);

  const row = await env.DB.prepare(`
    SELECT * FROM access_codes
    WHERE email = ? AND code = ? AND used = 0 AND expires_at > datetime('now')
    ORDER BY id DESC LIMIT 1
  `).bind(email, code).first();

  if (!row) return json({ ok: false, error: 'invalid_or_expired_access_code' }, 400);

  await env.DB.prepare('UPDATE access_codes SET used = 1 WHERE id = ?').bind(row.id).run();

  await env.DB.prepare(`
    INSERT INTO subscriptions (email, status, provider, provider_ref, created_at, updated_at)
    VALUES (?, 'approved', 'mercadopago', ?, datetime('now'), datetime('now'))
    ON CONFLICT(email) DO UPDATE SET status='approved', updated_at=datetime('now')
  `).bind(email, `code-${Date.now()}`).run();

  return json({ ok: true });
}

const PRICE_REF = {
  MXRF11: 10.3, HGLG11: 158.0, PETR4: 37.8, WEGE3: 53.0,
  VISC11: 108.0, KNRI11: 151.0, BBAS3: 31.0, VALE3: 55.0,
  IRIM11: 64.7, RZTR11: 96.8, KNCA11: 96.6, BRCO11: 117.9,
  VILG11: 86.5, XPLG11: 101.2, BTLG11: 103.4, HGRU11: 120.0,
  HGBS11: 20.18, CPTS11: 8.9, KDIF11: 100.5,
  ITUB4: 36.0, ABEV3: 13.2, EGIE3: 43.5, VBBR3: 23.0, B3SA3: 12.7,
  KLBN11: 21.5, KNIP11: 95.0, XPML11: 103.0, KNCR11: 103.5, IRDM11: 76.0
};

const METRIC_REF = {
  MXRF11: 1.04, HGLG11: 0.95, PETR4: 1.18, WEGE3: 8.4,
  HGBS11: 0.97, KNRI11: 0.93, BBAS3: 1.12, VALE3: 1.45,
  VISC11: 0.89, XPLG11: 0.86
};

const CRYPTO_MAP = { BTC:'bitcoin', ETH:'ethereum', SOL:'solana', XRP:'ripple', BNB:'binancecoin', ADA:'cardano', DOGE:'dogecoin', LTC:'litecoin', USDT:'tether' };
const CRYPTO_FALLBACK = { BTC:98000, ETH:3200, SOL:180, XRP:0.6, BNB:650, ADA:0.8, DOGE:0.12, LTC:90, USDT:1 };

async function marketAsset(request) {
  const url = new URL(request.url);
  const tickerRaw = String(url.searchParams.get('ticker') || '').trim().toUpperCase();
  const clsRaw = String(url.searchParams.get('cls') || '').trim().toUpperCase();
  const ticker = tickerRaw === 'BITCOIN' ? 'BTC' : tickerRaw;
  const cls = clsRaw || (ticker.endsWith('11') ? 'FII' : 'ACAO');

  let usdBrl = 5.2;
  try {
    const fx = await fetch('https://economia.awesomeapi.com.br/json/last/USD-BRL', { cf: { cacheTtl: 300, cacheEverything: true } }).then(r => r.json());
    const bid = Number(fx?.USDBRL?.bid);
    if (Number.isFinite(bid) && bid > 0) usdBrl = bid;
  } catch {}

  if (cls === 'CRIPTO') {
    const id = CRYPTO_MAP[ticker];
    if (!id) return json({ ok:false, error:'crypto_not_mapped' }, 400);

    const usd = CRYPTO_FALLBACK[ticker] || null;
    return json({ ok:true, ticker, cls:'CRIPTO', priceBrl: usd ? usd * usdBrl : null, metric: null, metricType:'chg24h', usdBrl });
  }

  return json({ ok:true, ticker, cls, priceBrl: PRICE_REF[ticker] ?? null, metric: METRIC_REF[ticker] ?? null, metricType:'pvp', usdBrl });
}

function decodeHtml(str='') {
  return String(str)
    .replace(/<!\[CDATA\[|\]\]>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}


async function marketBatch(request) {
  const body = await request.json().catch(()=>({}));
  const assets = Array.isArray(body?.assets) ? body.assets : [];

  let usdBrl = 5.2;
  try {
    const fx = await fetch('https://economia.awesomeapi.com.br/json/last/USD-BRL', { cf: { cacheTtl: 300, cacheEverything: true } }).then(r => r.json());
    const bid = Number(fx?.USDBRL?.bid);
    if (Number.isFinite(bid) && bid > 0) usdBrl = bid;
  } catch {}

  const normalized = assets.slice(0, 120).map((a) => {
    const tickerRaw = String(a?.ticker || '').trim().toUpperCase();
    const clsRaw = String(a?.cls || '').trim().toUpperCase();
    const ticker = tickerRaw === 'BITCOIN' ? 'BTC' : tickerRaw;
    const cls = clsRaw || (ticker.endsWith('11') ? 'FII' : 'ACAO');
    return { ticker, cls };
  });

  // Busca em lote no Yahoo para aumentar cobertura sem perder velocidade
  const yahooSymbols = [...new Set(normalized
    .filter(a => a.cls !== 'CRIPTO' && /^[A-Z0-9]{2,10}$/.test(a.ticker))
    .map(a => `${a.ticker}.SA`)
  )];

  const yahooByTicker = {};
  if (yahooSymbols.length) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);
      const quoteUrl = `https://query1.finance.yahoo.com/v7/finance/quote?symbols=${encodeURIComponent(yahooSymbols.join(','))}`;
      const y = await fetch(quoteUrl, { signal: controller.signal, cf: { cacheTtl: 60, cacheEverything: true } }).then(r => r.json());
      clearTimeout(timeout);
      const rows = y?.quoteResponse?.result || [];
      for (const row of rows) {
        const symbol = String(row?.symbol || '').toUpperCase();
        const ticker = symbol.replace('.SA', '');
        const price = Number(row?.regularMarketPrice);
        const ptb = Number(row?.priceToBook);
        yahooByTicker[ticker] = {
          priceBrl: Number.isFinite(price) ? price : null,
          pvp: Number.isFinite(ptb) ? ptb : null,
        };
      }
    } catch {}
  }

  // Fallback BRAPI para aumentar cobertura quando Yahoo falhar
  const brapiByTicker = {};
  const brapiTickers = [...new Set(normalized
    .filter(a => a.cls !== 'CRIPTO' && /^[A-Z0-9]{2,10}$/.test(a.ticker))
    .map(a => a.ticker)
  )];
  if (brapiTickers.length) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);
      const brapiUrl = `https://brapi.dev/api/quote/${encodeURIComponent(brapiTickers.join(','))}?fundamental=false&dividends=false`;
      const b = await fetch(brapiUrl, { signal: controller.signal, cf: { cacheTtl: 60, cacheEverything: true } }).then(r => r.json());
      clearTimeout(timeout);
      const rows = Array.isArray(b?.results) ? b.results : [];
      for (const row of rows) {
        const ticker = String(row?.symbol || '').toUpperCase();
        const price = Number(row?.regularMarketPrice);
        if (!ticker) continue;
        brapiByTicker[ticker] = {
          priceBrl: Number.isFinite(price) ? price : null,
        };
      }
    } catch {}
  }

  const out = normalized.map(({ ticker, cls }) => {
    if (cls === 'CRIPTO') {
      const usd = CRYPTO_FALLBACK[ticker] || null;
      return { ticker, cls, priceBrl: usd ? usd * usdBrl : null, metric: null, metricType:'chg24h', usdBrl };
    }

    const y = yahooByTicker[ticker];
    const b = brapiByTicker[ticker];
    const priceBrl = Number.isFinite(y?.priceBrl)
      ? y.priceBrl
      : (Number.isFinite(b?.priceBrl) ? b.priceBrl : (PRICE_REF[ticker] ?? null));
    const metric = Number.isFinite(METRIC_REF[ticker]) ? METRIC_REF[ticker] : (Number.isFinite(y?.pvp) ? y.pvp : null);
    const metricType = Number.isFinite(metric) ? 'pvp' : 'na';

    return { ticker, cls, priceBrl, metric, metricType, usdBrl };
  });

  // 2ª camada: tenta preencher apenas os faltantes sem bloquear tudo
  const missing = out.filter(it => it.cls !== 'CRIPTO' && !Number.isFinite(it.priceBrl)).slice(0, 10);
  await Promise.allSettled(missing.map(async (it) => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 1200);
      const u = `https://query1.finance.yahoo.com/v7/finance/quote?symbols=${encodeURIComponent(it.ticker + '.SA')}`;
      const y = await fetch(u, { signal: controller.signal, cf: { cacheTtl: 60, cacheEverything: true } }).then(r => r.json());
      clearTimeout(timeout);
      const row = y?.quoteResponse?.result?.[0];
      const price = Number(row?.regularMarketPrice);
      const ptb = Number(row?.priceToBook);
      if (Number.isFinite(price)) it.priceBrl = price;
      if (!Number.isFinite(it.metric) && Number.isFinite(ptb)) it.metric = ptb;
    } catch {}
  }));

  return json({ ok:true, items: out, usdBrl });
}

async function marketNews(request) {
  const url = new URL(request.url);
  const raw = String(url.searchParams.get('tickers') || '');
  const limit = Math.min(20, Math.max(1, Number(url.searchParams.get('limit') || 12)));
  const tickers = [...new Set(raw.split(',').map(t => t.trim().toUpperCase()).filter(Boolean))].slice(0, 12);
  if (!tickers.length) return json({ ok:true, news:[] });

  // Resposta rápida e estável (sem depender de scraping externo em tempo real)
  const news = tickers.flatMap(ticker => ([
    {
      ticker,
      title: `Acompanhar notícias recentes de ${ticker}`,
      url: `https://news.google.com/search?q=${encodeURIComponent(ticker + ' mercado financeiro when:7d')}&hl=pt-BR&gl=BR&ceid=BR:pt-419`,
      source: 'Google News',
      time: new Date().toISOString(),
    },
    {
      ticker,
      title: `Pesquisar análises e fatos relevantes de ${ticker}`,
      url: `https://www.google.com/search?q=${encodeURIComponent(ticker + ' fatos relevantes ri')}`,
      source: 'Web',
      time: new Date().toISOString(),
    }
  ]));

  return json({ ok:true, news: news.slice(0, limit) });
}
