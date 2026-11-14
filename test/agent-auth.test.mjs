import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { agentAuth } from '../lib/agent-auth.mjs';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test', alg: 'RS256', use: 'sig' };
const authenticate = agentAuth({ fetchKeys: async () => ({ ok: true, json: async () => ({ keys: [jwk] }) }) });
const base = { iss: 'https://account.osmike.com', aud: 'account.osmike.com', sub: 'person-one', exp: Date.now() / 1000 + 300, scope: 'calendar:read', act: { iss: 'a2a', sub: 'agent-one' } };
function token(claims = base, header = { alg: 'RS256', kid: 'test' }) {
  const data = [header, claims].map(v => Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  return `${data}.${sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url')}`;
}
async function call(jwt, method = 'GET') {
  const req = { headers: jwt ? { authorization: `Bearer ${jwt}` } : {}, method };
  const result = { req, status: 200, next: false };
  const res = { status(n) { result.status = n; return this; }, json(body) { result.body = body; } };
  await authenticate(req, res, () => { result.next = true; });
  return result;
}
test('each verified person keeps their own subject and original backend credential', async () => {
  for (const sub of ['person-one', 'person-two']) {
    const jwt = token({ ...base, sub }); const r = await call(jwt);
    assert.equal(r.next, true); assert.equal(r.req.agentAuth.user.sub, sub); assert.equal(r.req.agentAuth.token, jwt);
  }
});
test('all agent mutations are forbidden', async () => {
  for (const method of ['POST', 'PATCH', 'DELETE', 'PUT']) assert.equal((await call(token(), method)).status, 403);
});
test('reject wrong issuer, audience, expiry, actor, signature and algorithm', async () => {
  for (const patch of [{ iss: 'other' }, { aud: 'events' }, { exp: 0 }, { exp: '9999999999' }, { nbf: Date.now() / 1000 + 600 }, { act: {} }, { sub: '' }]) assert.equal((await call(token({ ...base, ...patch }))).status, 401);
  assert.equal((await call(token(base, { alg: 'HS256', kid: 'test' }))).status, 401);
  const jwt = token(); const [h,b,s] = jwt.split('.');
  assert.equal((await call(`${h}.${b}.${(s[0] === 'A' ? 'B' : 'A') + s.slice(1)}`)).status, 401);
});
test('require exact calendar scope and preserve browser session path', async () => {
  assert.equal((await call(token({ ...base, scope: 'calendar:readmore' }))).status, 403);
  assert.equal((await call()).next, true);
});
