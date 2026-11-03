// Flixnet backend on Cloudflare Workers
//  - GET  /<tmdb path>        cached TMDB metadata proxy (keeps the TMDB key off the device)
//  - POST /auth/register      create account            -> { token, user }
//  - POST /auth/login         sign in                   -> { token, user }
//  - GET  /auth/me            current user              (Bearer token)
//  - DELETE /auth/account     delete account + library  (Bearer token)
//  - GET/PUT /library         per-user library backup   (Bearer token)
//
// Secrets (never commit them):  TMDB_API_KEY, JWT_SECRET
// Binding: DB (D1)

const TMDB = 'https://api.themoviedb.org/3';
const TMDB_TTL = 600; // seconds
const JWT_TTL = 60 * 60 * 24 * 30; // 30 days
const PBKDF2_ITERATIONS = 100000; // the maximum Workers allows
const MAX_LIBRARY_BYTES = 1_000_000;

const ALLOWED = [
  /^\/trending\/(all|movie|tv)\/(day|week)$/,
  /^\/(movie|tv)\/(now_playing|upcoming|popular|on_the_air|top_rated)$/,
  /^\/search\/(multi|movie|tv)$/,
  /^\/genre\/(movie|tv)\/list$/,
  /^\/discover\/(movie|tv)$/,
  /^\/(movie|tv)\/\d+$/,
  /^\/(movie|tv)\/\d+\/(similar|recommendations)$/,
  /^\/tv\/\d+\/season\/\d+$/,
  /^\/person\/\d+\/combined_credits$/,
];

const enc = new TextEncoder();

// ---------- small helpers ----------
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
};

function withCors(res) {
  const r = new Response(res.body, res);
  for (const [k, v] of Object.entries(CORS)) r.headers.set(k, v);
  return r;
}
const json = (data, status = 200) =>
  withCors(new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }));
const fail = (message, status = 400) => json({ error: message }, status);

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- passwords (PBKDF2-SHA256 via WebCrypto) ----------
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    key,
    256,
  );
  return new Uint8Array(bits);
}

// ---------- JWT (HS256) ----------
async function hmacKey(secret, usages) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, usages);
}

async function signJwt(payload, secret) {
  const header = b64u(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret, ['sign']), enc.encode(`${header}.${body}`));
  return `${header}.${body}.${b64u(sig)}`;
}

async function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const ok = await crypto.subtle.verify(
      'HMAC',
      await hmacKey(secret, ['verify']),
      unb64u(parts[2]),
      enc.encode(`${parts[0]}.${parts[1]}`),
    );
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(unb64u(parts[1])));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function authed(request, env) {
  const h = request.headers.get('Authorization') || '';
  if (!h.startsWith('Bearer ')) return null;
  return verifyJwt(h.slice(7), env.JWT_SECRET);
}

async function issueToken(user, env) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt({ sub: user.id, email: user.email, iat: now, exp: now + JWT_TTL }, env.JWT_SECRET);
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// ---------- route handlers ----------
async function register(request, env) {
  const body = await readJson(request);
  const email = String(body?.email || '').trim().toLowerCase();
  const password = String(body?.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return fail('Enter a valid email address.');
  if (password.length < 8 || password.length > 128) return fail('Password must be 8 to 128 characters.');

  const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (exists) return fail('An account with this email already exists.', 409);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);
  const user = { id: crypto.randomUUID(), email };
  try {
    await env.DB.prepare('INSERT INTO users (id, email, pw_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(user.id, email, b64u(hash), b64u(salt), Date.now())
      .run();
  } catch {
    return fail('An account with this email already exists.', 409);
  }
  return json({ token: await issueToken(user, env), user: { email } }, 201);
}

async function login(request, env) {
  const body = await readJson(request);
  const email = String(body?.email || '').trim().toLowerCase();
  const password = String(body?.password || '');
  if (!email || !password || password.length > 128) return fail('Invalid email or password.', 401);

  const row = await env.DB.prepare('SELECT id, email, pw_hash, salt FROM users WHERE email = ?').bind(email).first();
  if (!row) {
    await hashPassword(password, new Uint8Array(16)); // keep timing similar for unknown emails
    return fail('Invalid email or password.', 401);
  }
  const hash = await hashPassword(password, unb64u(row.salt));
  if (!constantTimeEqual(hash, unb64u(row.pw_hash))) return fail('Invalid email or password.', 401);
  return json({ token: await issueToken(row, env), user: { email: row.email } });
}

async function me(request, env) {
  const claims = await authed(request, env);
  if (!claims) return fail('Please sign in again.', 401);
  const row = await env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(claims.sub).first();
  if (!row) return fail('Account not found.', 401);
  return json({ user: { email: row.email } });
}

async function deleteAccount(request, env) {
  const claims = await authed(request, env);
  if (!claims) return fail('Please sign in again.', 401);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM library WHERE user_id = ?').bind(claims.sub),
    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(claims.sub),
  ]);
  return json({ ok: true });
}

async function getLibrary(request, env) {
  const claims = await authed(request, env);
  if (!claims) return fail('Please sign in again.', 401);
  const row = await env.DB.prepare('SELECT data, updated_at FROM library WHERE user_id = ?').bind(claims.sub).first();
  return json({ data: row ? JSON.parse(row.data) : null, updated_at: row ? row.updated_at : null });
}

async function putLibrary(request, env) {
  const claims = await authed(request, env);
  if (!claims) return fail('Please sign in again.', 401);
  const text = await request.text();
  if (text.length > MAX_LIBRARY_BYTES) return fail('Library is too large.', 413);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return fail('Invalid JSON.');
  }
  const data = parsed?.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return fail('Expected { "data": { ... } }.');

  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO library (user_id, data, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
  )
    .bind(claims.sub, JSON.stringify(data), now)
    .run();
  return json({ ok: true, updated_at: now });
}

async function tmdbProxy(request, env, ctx, url) {
  if (!ALLOWED.some((re) => re.test(url.pathname))) return fail('Not found.', 404);

  const cache = caches.default;
  const cacheKey = new Request(url.toString(), { method: 'GET' });
  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  const upstream = new URL(TMDB + url.pathname);
  url.searchParams.forEach((v, k) => {
    if (k !== 'api_key') upstream.searchParams.set(k, v); // never trust a client-supplied key
  });
  upstream.searchParams.set('api_key', env.TMDB_API_KEY);

  const r = await fetch(upstream.toString());
  const res = withCors(new Response(r.body, r));
  if (r.ok) {
    res.headers.set('Cache-Control', `public, max-age=${TMDB_TTL}`);
    ctx.waitUntil(cache.put(cacheKey, res.clone()));
  }
  return res;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return withCors(new Response(null, { status: 204 }));

    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    try {
      if (pathname === '/auth/register' && method === 'POST') return await register(request, env);
      if (pathname === '/auth/login' && method === 'POST') return await login(request, env);
      if (pathname === '/auth/me' && method === 'GET') return await me(request, env);
      if (pathname === '/auth/account' && method === 'DELETE') return await deleteAccount(request, env);
      if (pathname === '/library' && method === 'GET') return await getLibrary(request, env);
      if (pathname === '/library' && method === 'PUT') return await putLibrary(request, env);
      if (method === 'GET') return await tmdbProxy(request, env, ctx, url);
      return fail('Method not allowed.', 405);
    } catch (e) {
      console.error(e);
      return fail('Server error.', 500);
    }
  },
};
