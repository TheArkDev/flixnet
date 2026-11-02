// Cloudflare Worker: TMDB proxy that keeps the API key off the device and
// caches common responses at Cloudflare's edge. Metadata only.
const TMDB = 'https://api.themoviedb.org/3';
const TTL = 600; // seconds

const ALLOWED = [
  /^\/trending\/(movie|tv)\/day$/,
  /^\/(movie|tv)\/(now_playing|upcoming|popular|on_the_air|top_rated)$/,
  /^\/search\/multi$/,
  /^\/genre\/(movie|tv)\/list$/,
  /^\/discover\/(movie|tv)$/,
  /^\/(movie|tv)\/\d+$/,
  /^\/tv\/\d+\/season\/\d+$/,
  /^\/person\/\d+\/combined_credits$/,
];

function withCors(res) {
  const r = new Response(res.body, res);
  r.headers.set('Access-Control-Allow-Origin', '*');
  r.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  return r;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return withCors(new Response(null, { status: 204 }));
    if (request.method !== 'GET') return withCors(new Response('Method not allowed', { status: 405 }));

    const url = new URL(request.url);
    if (!ALLOWED.some((re) => re.test(url.pathname))) {
      return withCors(new Response('Not found', { status: 404 }));
    }

    const cache = caches.default;
    const cacheKey = new Request(url.toString(), { method: 'GET' });
    const hit = await cache.match(cacheKey);
    if (hit) return hit;

    const upstream = new URL(TMDB + url.pathname);
    url.searchParams.forEach((v, k) => {
      if (k !== 'api_key') upstream.searchParams.set(k, v); // never trust a client key
    });
    upstream.searchParams.set('api_key', env.TMDB_API_KEY);

    const r = await fetch(upstream.toString());
    const res = withCors(new Response(r.body, r));
    if (r.ok) {
      res.headers.set('Cache-Control', `public, max-age=${TTL}`);
      ctx.waitUntil(cache.put(cacheKey, res.clone()));
    }
    return res;
  },
};
