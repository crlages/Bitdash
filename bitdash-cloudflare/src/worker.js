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
        return C(await marketBatch(request, env));
      }

      if (url.pathname === '/assets/search' && request.method === 'GET') {
        return C(await assetsSearch(request, env));
      }

      if (url.pathname === '/assets/sync' && request.method === 'POST') {
        return C(await assetsSync(env));
      }

      if (url.pathname === '/fundamentals/sync' && request.method === 'POST') {
        return C(await fundamentalsSync(env));
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
  VISC11: 0.89, XPLG11: 0.86,
  ITUB4: 1.32, ABEV3: 2.55, EGIE3: 2.10, VBBR3: 1.38,
  KLBN11: 1.22, KNIP11: 0.98, XPML11: 0.92, BTLG11: 0.95,
  KNCR11: 1.01, HGRU11: 0.97, IRDM11: 0.89
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


async function marketBatch(request, env) {
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

  // aprende tickers em tempo real (inclusive modo grátis), sem depender de carteira salva no DB
  try {
    await ensureAssetsUniverseSchema(env);
    const uniqueTickers = [...new Set(normalized.map(x => x.ticker).filter(Boolean))];
    for (const t of uniqueTickers) {
      await env.DB.prepare(`
        INSERT INTO assets_universe (ticker, name, asset_type, source, is_active, updated_at)
        VALUES (?, NULL, ?, 'runtime', 1, datetime('now'))
        ON CONFLICT(ticker) DO UPDATE SET
          asset_type=COALESCE(excluded.asset_type, assets_universe.asset_type),
          is_active=1,
          updated_at=datetime('now')
      `).bind(t, classifyTickerUniverse(t)).run();
    }
  } catch {}

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
        const pe = Number(row?.trailingPE);
        const fpe = Number(row?.forwardPE);
        yahooByTicker[ticker] = {
          priceBrl: Number.isFinite(price) ? price : null,
          pvp: Number.isFinite(ptb) ? ptb : null,
          pe: Number.isFinite(pe) ? pe : (Number.isFinite(fpe) ? fpe : null),
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

  const fundamentalsByTicker = await loadFundamentalsForTickers(env, normalized.map(x => x.ticker));

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

    let metric = null;
    let metricType = 'na';
    const clsNorm = String(cls || '').toUpperCase();
    const isEquityLike = clsNorm === 'ACAO' || clsNorm === 'AÇÃO' || clsNorm === 'BDR' || clsNorm === 'ETF' || clsNorm === 'ETF EUA';
    const f = fundamentalsByTicker[ticker] || {};

    if (Number.isFinite(METRIC_REF[ticker])) {
      metric = METRIC_REF[ticker];
      metricType = 'pvp';
    } else if (Number.isFinite(y?.pvp)) {
      metric = y.pvp;
      metricType = 'pvp';
    } else if (Number.isFinite(f?.pvp)) {
      metric = f.pvp;
      metricType = 'pvp';
    } else if (isEquityLike && Number.isFinite(y?.pe)) {
      metric = y.pe;
      metricType = 'pl';
    } else if (isEquityLike && Number.isFinite(f?.pl)) {
      metric = f.pl;
      metricType = 'pl';
    } else {
      // fallback universal indicativo para não deixar ativo sem referência
      if (clsNorm === 'FII') {
        metric = 0.99;
        metricType = 'ref';
      } else if (isEquityLike) {
        metric = 1.35;
        metricType = 'ref';
      }
    }

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

async function ensureAssetsUniverseSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS assets_universe (
      ticker TEXT PRIMARY KEY,
      name TEXT,
      asset_type TEXT,
      source TEXT NOT NULL DEFAULT 'brapi',
      is_active INTEGER NOT NULL DEFAULT 1,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_assets_universe_type ON assets_universe(asset_type)').run();
}

async function ensureFundamentalsSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS fundamentals_cache (
      ticker TEXT PRIMARY KEY,
      pvp REAL,
      pl REAL,
      source TEXT NOT NULL DEFAULT 'brapi',
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_fundamentals_updated ON fundamentals_cache(updated_at)').run();
}

async function loadFundamentalsForTickers(env, tickers) {
  await ensureFundamentalsSchema(env);
  const list = [...new Set((tickers || []).map(t => String(t || '').trim().toUpperCase()).filter(Boolean))].slice(0, 200);
  if (!list.length) return {};

  const placeholders = list.map(() => '?').join(',');
  const q = `SELECT ticker, pvp, pl FROM fundamentals_cache WHERE ticker IN (${placeholders})`;
  const rows = await env.DB.prepare(q).bind(...list).all();
  const out = {};
  for (const r of (rows?.results || [])) {
    out[String(r.ticker).toUpperCase()] = {
      pvp: Number.isFinite(Number(r.pvp)) ? Number(r.pvp) : null,
      pl: Number.isFinite(Number(r.pl)) ? Number(r.pl) : null,
    };
  }
  return out;
}

async function fundamentalsSync(env) {
  await ensureAssetsUniverseSchema(env);
  await ensureFundamentalsSchema(env);

  const rows = await env.DB.prepare(`
    SELECT ticker
    FROM assets_universe
    WHERE is_active = 1
    ORDER BY updated_at DESC
    LIMIT 350
  `).all();
  const tickers = (rows?.results || []).map(r => String(r.ticker || '').toUpperCase()).filter(Boolean);
  if (!tickers.length) return json({ ok: true, synced: 0 });

  let synced = 0;

  // 1) seed com métricas de referência já conhecidas
  for (const t of tickers) {
    const pvpRef = Number(METRIC_REF[t]);
    if (Number.isFinite(pvpRef)) {
      await env.DB.prepare(`
        INSERT INTO fundamentals_cache (ticker, pvp, pl, source, updated_at)
        VALUES (?, ?, NULL, 'seed', datetime('now'))
        ON CONFLICT(ticker) DO UPDATE SET
          pvp=COALESCE(excluded.pvp, fundamentals_cache.pvp),
          updated_at=datetime('now')
      `).bind(t, pvpRef).run();
      synced++;
    }
  }

  // 2) tenta enriquecer por lotes no Yahoo (ptb/pe)
  const yahooSymbols = tickers.map(t => `${t}.SA`);
  const chunkSize = 60;
  for (let i = 0; i < yahooSymbols.length; i += chunkSize) {
    const chunk = yahooSymbols.slice(i, i + chunkSize);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3500);
      const url = `https://query1.finance.yahoo.com/v7/finance/quote?symbols=${encodeURIComponent(chunk.join(','))}`;
      const y = await fetch(url, { signal: controller.signal, cf: { cacheTtl: 1200, cacheEverything: true } }).then(r => r.json());
      clearTimeout(timeout);
      const rowsY = y?.quoteResponse?.result || [];
      for (const r of rowsY) {
        const symbol = String(r?.symbol || '').toUpperCase();
        const ticker = symbol.replace('.SA', '');
        if (!ticker) continue;
        const pvp = Number(r?.priceToBook);
        const pe = Number(r?.trailingPE);
        const fpe = Number(r?.forwardPE);
        await env.DB.prepare(`
          INSERT INTO fundamentals_cache (ticker, pvp, pl, source, updated_at)
          VALUES (?, ?, ?, 'yahoo', datetime('now'))
          ON CONFLICT(ticker) DO UPDATE SET
            pvp=COALESCE(excluded.pvp, fundamentals_cache.pvp),
            pl=COALESCE(excluded.pl, fundamentals_cache.pl),
            source='yahoo',
            updated_at=datetime('now')
        `).bind(
          ticker,
          Number.isFinite(pvp) ? pvp : null,
          Number.isFinite(pe) ? pe : (Number.isFinite(fpe) ? fpe : null)
        ).run();
        synced++;
      }
    } catch {}
  }

  // 3) BRAPI como complemento
  const chunkSizeB = 40;
  for (let i = 0; i < tickers.length; i += chunkSizeB) {
    const chunk = tickers.slice(i, i + chunkSizeB);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const url = `https://brapi.dev/api/quote/${encodeURIComponent(chunk.join(','))}?fundamental=true&dividends=false`;
      const j = await fetch(url, { signal: controller.signal, cf: { cacheTtl: 1800, cacheEverything: true } }).then(r => r.json());
      clearTimeout(timeout);

      const res = Array.isArray(j?.results) ? j.results : [];
      for (const r of res) {
        const ticker = String(r?.symbol || '').toUpperCase();
        if (!ticker) continue;

        const key = r?.fundamental?.financialData || r?.fundamental || {};
        const pvp = Number(key?.priceToBook || key?.priceToBookRatio || key?.pvp);
        const pl = Number(key?.priceEarnings || key?.priceToEarnings || key?.pe || key?.trailingPE);

        await env.DB.prepare(`
          INSERT INTO fundamentals_cache (ticker, pvp, pl, source, updated_at)
          VALUES (?, ?, ?, 'brapi', datetime('now'))
          ON CONFLICT(ticker) DO UPDATE SET
            pvp=COALESCE(excluded.pvp, fundamentals_cache.pvp),
            pl=COALESCE(excluded.pl, fundamentals_cache.pl),
            source='brapi',
            updated_at=datetime('now')
        `).bind(
          ticker,
          Number.isFinite(pvp) ? pvp : null,
          Number.isFinite(pl) ? pl : null
        ).run();
        synced++;
      }
    } catch {}
  }

  return json({ ok: true, synced });
}

function classifyTickerUniverse(ticker='') {
  const t = String(ticker).toUpperCase();
  if (/^[A-Z0-9]{4,10}11$/.test(t)) return 'FUNDO';
  if (/^[A-Z]{4}(3|4|5|6)$/.test(t)) return 'ACAO';
  if (/^[A-Z]{4,6}\d{2}$/.test(t)) return 'BDR';
  return 'OUTRO';
}

async function assetsSync(env) {
  await ensureAssetsUniverseSchema(env);

  // BRAPI lista de ações brasileiras; alguns fundos também aparecem em endpoints de quote
  const out = [];
  try {
    const j = await fetch('https://brapi.dev/api/available?search=stocks', { cf: { cacheTtl: 3600, cacheEverything: true } }).then(r => r.json());
    const stocks = Array.isArray(j?.stocks) ? j.stocks : [];
    for (const t of stocks) {
      const ticker = String(t || '').trim().toUpperCase();
      if (!ticker) continue;
      out.push({ ticker, name: null, asset_type: classifyTickerUniverse(ticker) });
    }
  } catch {}

  // seed de fundos mais comuns para garantir cobertura inicial
  const fundosSeed = ['MXRF11','HGLG11','KNIP11','XPML11','BTLG11','VISC11','KNCR11','HGBS11','HGRU11','IRDM11','XPLG11','VILG11','BRCO11','CPTS11'];
  for (const t of fundosSeed) {
    out.push({ ticker: t, name: null, asset_type: 'FUNDO' });
  }

  // adiciona tickers já usados por usuários (carteiras salvas)
  try {
    const pr = await env.DB.prepare('SELECT data_json FROM portfolios ORDER BY updated_at DESC LIMIT 300').all();
    for (const row of (pr?.results || [])) {
      try {
        const arr = JSON.parse(String(row?.data_json || '[]'));
        if (!Array.isArray(arr)) continue;
        for (const it of arr) {
          const ticker = String(it?.ticker || '').trim().toUpperCase();
          if (!ticker) continue;
          out.push({ ticker, name: null, asset_type: classifyTickerUniverse(ticker) });
        }
      } catch {}
    }
  } catch {}

  const byTicker = new Map();
  for (const a of out) byTicker.set(a.ticker, a);
  const unique = [...byTicker.values()];

  for (const a of unique) {
    await env.DB.prepare(`
      INSERT INTO assets_universe (ticker, name, asset_type, source, is_active, updated_at)
      VALUES (?, ?, ?, 'brapi', 1, datetime('now'))
      ON CONFLICT(ticker) DO UPDATE SET
        name=COALESCE(excluded.name, assets_universe.name),
        asset_type=COALESCE(excluded.asset_type, assets_universe.asset_type),
        is_active=1,
        updated_at=datetime('now')
    `).bind(a.ticker, a.name, a.asset_type).run();
  }

  // Atualiza fundamentos em seguida para reduzir "indisponível" no dashboard
  let fundamentalsSynced = 0;
  try {
    const fs = await fundamentalsSync(env);
    const fjson = await fs.json();
    fundamentalsSynced = Number(fjson?.synced || 0);
  } catch {}

  return json({ ok: true, synced: unique.length, fundamentalsSynced });
}

async function assetsSearch(request, env) {
  await ensureAssetsUniverseSchema(env);
  const url = new URL(request.url);
  const q = String(url.searchParams.get('q') || '').trim().toUpperCase();
  const limit = Math.min(30, Math.max(1, Number(url.searchParams.get('limit') || 12)));

  if (!q) {
    const rows = await env.DB.prepare(`
      SELECT ticker, name, asset_type
      FROM assets_universe
      WHERE is_active = 1
      ORDER BY updated_at DESC
      LIMIT ?
    `).bind(limit).all();
    return json({ ok: true, items: rows?.results || [] });
  }

  const rows = await env.DB.prepare(`
    SELECT ticker, name, asset_type
    FROM assets_universe
    WHERE is_active = 1 AND (ticker LIKE ? OR name LIKE ?)
    ORDER BY CASE WHEN ticker = ? THEN 0 WHEN ticker LIKE ? THEN 1 ELSE 2 END, ticker ASC
    LIMIT ?
  `).bind(`${q}%`, `%${q}%`, q, `${q}%`, limit).all();

  return json({ ok: true, items: rows?.results || [] });
}
