import { createPublicKey, verify } from 'node:crypto';

// Only trust the account's fixed JWKS endpoint, never a URL supplied by a JWT.
export function agentAuth({ issuer = 'https://account.osmike.com', fetchKeys = () => fetch(`${issuer}/oauth/jwks.json`, { signal: AbortSignal.timeout(10_000) }) } = {}) {
  let keys = [], expires = 0, pending;
  async function refresh() {
    if (!pending) pending = (async () => {
      const response = await fetchKeys();
      if (!response.ok) throw new Error('jwks_unavailable');
      const data = await response.json();
      if (!Array.isArray(data.keys)) throw new Error('invalid_jwks');
      keys = data.keys; expires = Date.now() + 300_000;
    })().finally(() => { pending = undefined; });
    await pending;
  }
  return async (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) return next();
    try {
      if (authorization.length > 16384) throw new Error('invalid_token');
      const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(authorization);
      if (!match) throw new Error('invalid_token');
      const token = match[1], [head, body, signature] = token.split('.');
      const header = JSON.parse(Buffer.from(head, 'base64url'));
      const claims = JSON.parse(Buffer.from(body, 'base64url'));
      if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('invalid_token');
      if (Date.now() >= expires) await refresh();
      let key = keys.find(k => k.kid === header.kid && k.kty === 'RSA' && (!k.use || k.use === 'sig') && (!k.alg || k.alg === 'RS256'));
      if (!key) { await refresh(); key = keys.find(k => k.kid === header.kid && k.kty === 'RSA' && (!k.use || k.use === 'sig') && (!k.alg || k.alg === 'RS256')); }
      if (!key || !verify('RSA-SHA256', Buffer.from(`${head}.${body}`), createPublicKey({ key, format: 'jwk' }), Buffer.from(signature, 'base64url'))) throw new Error('invalid_token');
      const now = Date.now() / 1000;
      if (claims.iss !== issuer || !(Array.isArray(claims.aud) ? claims.aud : [claims.aud]).includes('account.osmike.com') ||
          typeof claims.sub !== 'string' || !claims.sub || typeof claims.exp !== 'number' || claims.exp <= now ||
          (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf > now)) ||
          claims.act?.iss !== 'a2a' || typeof claims.act.sub !== 'string' || !claims.act.sub) throw new Error('invalid_token');
      if (typeof claims.scope !== 'string' || !claims.scope.split(/\s+/).includes('calendar:read')) return res.status(403).json({ error: 'insufficient_scope' });
      if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return res.status(403).json({ error: 'agent_read_only' });
      req.agentAuth = { token, user: { sub: claims.sub }, agent: claims.act.sub };
      next();
    } catch { res.status(401).json({ error: 'invalid_token' }); }
  };
}
