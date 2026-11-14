// MikeCalendar — calendar.osmike.com
// The human-facing MikeOS calendar UI. Reads/writes the user's events from the
// MikeOS-native calendar backend (mikeos-events @ calendar-api.osmike.com) using the
// signed-in user's account.osmike.com Bearer token (dual-auth). Meetings scheduled in
// meetings.osmike.com appear here automatically (they are type:"calendar" events with a
// room_id + join_url). Auth flow copied verbatim from mikeos-office-web. Zero Google.
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import { agentAuth } from './lib/agent-auth.mjs';

const {
  PORT = 8096,
  ISSUER = 'https://account.osmike.com',
  CLIENT_ID = 'calendar-web',
  CALENDAR_URL = 'http://mikeos-events:8000',   // internal on deploy_default
  COOKIE_SECRET = crypto.randomBytes(24).toString('hex'),
} = process.env;

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser(COOKIE_SECRET));

const sessions = new Map();
const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const decodeJwt = (jwt) => { try { return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString('utf8')); } catch { return {}; } };
const cookieOpts = { httpOnly: true, secure: true, sameSite: 'lax', signed: true };
const sessionOf = (req) => sessions.get(req.signedCookies.sid);
const redirectUriFor = (req) => `https://${req.hostname}/auth/callback`;

// ---- OAuth (Auth Code + PKCE / S256) — copied from mikeos-office-web ----
app.get('/auth/login', (req, res) => {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));
  res.cookie('pkce', verifier, { ...cookieOpts, maxAge: 10 * 60_000 });
  res.cookie('ostate', state, { ...cookieOpts, maxAge: 10 * 60_000 });
  const u = new URL(`${ISSUER}/oauth/authorize`);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', CLIENT_ID);
  u.searchParams.set('redirect_uri', redirectUriFor(req));
  u.searchParams.set('scope', 'openid profile email');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  res.redirect(u.toString());
});

app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  const verifier = req.signedCookies.pkce;
  if (!code || !state || state !== req.signedCookies.ostate || !verifier) return res.status(400).send('Auth state mismatch — <a href="/">back</a>');
  try {
    const body = new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: CLIENT_ID, redirect_uri: redirectUriFor(req) });
    const r = await fetch(`${ISSUER}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    if (!r.ok) { console.warn('token exchange failed', r.status); return res.status(502).send('Sign-in failed — <a href="/">back</a>'); }
    const tok = await r.json();
    const claims = decodeJwt(tok.id_token || tok.access_token || '');
    const user = { sub: claims.sub, email: claims.email, name: claims.name || claims.preferred_username };
    if ((!user.email || !user.name) && tok.access_token) {
      try { const ui = await fetch(`${ISSUER}/oauth/userinfo`, { headers: { Authorization: `Bearer ${tok.access_token}` } });
        if (ui.ok) { const info = await ui.json(); user.sub = user.sub || info.sub; user.email = user.email || info.email; user.name = user.name || info.name || info.preferred_username || info.email; } } catch {}
    }
    if (!user.name) user.name = user.email || 'MikeOS user';
    const sid = b64url(crypto.randomBytes(24));
    sessions.set(sid, { access_token: tok.access_token, refresh_token: tok.refresh_token, expires_at: Date.now() + (tok.expires_in || 3600) * 1000, user });
    res.clearCookie('pkce', cookieOpts); res.clearCookie('ostate', cookieOpts);
    res.cookie('sid', sid, { ...cookieOpts, maxAge: 30 * 24 * 60 * 60_000 });
    res.redirect('/');
  } catch (e) { console.warn('callback error', e); res.status(502).send('Sign-in error — <a href="/">back</a>'); }
});

app.post('/auth/logout', (req, res) => { const sid = req.signedCookies.sid; if (sid) sessions.delete(sid); res.clearCookie('sid', cookieOpts); res.json({ ok: true }); });
app.use('/api', agentAuth());
app.get('/api/me', (req, res) => { const s = sessionOf(req); if (req.agentAuth) return res.json({ authenticated: true, user: req.agentAuth.user, agent: req.agentAuth.agent, read_only: true }); res.json(s ? { authenticated: true, user: s.user } : { authenticated: false }); });

async function accessTokenFor(req) {
  if (req.agentAuth) return req.agentAuth.token;
  const s = sessionOf(req); if (!s) return null;
  if (Date.now() < s.expires_at - 60_000) return s.access_token;
  if (!s.refresh_token) return s.access_token;
  try {
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: s.refresh_token, client_id: CLIENT_ID });
    const r = await fetch(`${ISSUER}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    if (r.ok) { const t = await r.json(); s.access_token = t.access_token || s.access_token; if (t.refresh_token) s.refresh_token = t.refresh_token; s.expires_at = Date.now() + (t.expires_in || 3600) * 1000; }
  } catch (e) { console.warn('refresh', e.message); }
  return s.access_token;
}
const requireAuth = (req, res) => { const s = req.agentAuth || sessionOf(req); if (!s) { res.status(401).json({ error: 'not_authenticated' }); return null; } return s; };
const bearer = (tok) => ({ Authorization: `Bearer ${tok}` });
const nowIso = () => new Date().toISOString();
const toIso = (s) => { if (!s) return null; const ms = Date.parse(s); return Number.isFinite(ms) ? new Date(ms).toISOString() : null; };

// Normalize a backend event -> the calendar UI shape.
function toUiEvent(ev) {
  const p = ev.payload || {};
  return {
    id: ev.id, title: p.title || '(no title)',
    start: p.start || ev.ts, end: p.end || null,
    all_day: !!p.all_day, location: p.location || '', description: p.description || '',
    room_id: p.room_id || null, join_url: p.join_url || null,
    is_meeting: !!p.room_id, app: ev.app || null,
  };
}

// ---- calendar CRUD (forward the user's Bearer to the MikeOS calendar backend) ----
app.get('/api/events', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const limit = req.query.limit === undefined ? 1000 : Number(req.query.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) return res.status(400).json({ error: 'bad_limit' });
  const tok = await accessTokenFor(req);
  try {
    const r = await fetch(`${CALENDAR_URL}/api/events?type=calendar&limit=${limit}`, { headers: bearer(tok) });
    if (!r.ok) return res.status(502).json({ error: 'calendar_error', status: r.status });
    const data = await r.json();
    const events = (Array.isArray(data) ? data : data.events || []).filter((e) => e?.type === 'calendar').map(toUiEvent);
    res.json({ events });
  } catch (e) { console.warn('list', e.message); res.status(502).json({ error: 'calendar_unreachable' }); }
});

app.post('/api/events', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const tok = await accessTokenFor(req);
  const startIso = toIso(req.body?.start);
  if (!startIso) return res.status(400).json({ error: 'bad_start' });
  const payload = {
    title: String(req.body?.title || '').trim() || 'Untitled event',
    start: startIso, end: toIso(req.body?.end) || null,
    all_day: !!req.body?.all_day, location: String(req.body?.location || '').slice(0, 300),
    description: String(req.body?.description || '').slice(0, 4000),
  };
  const event = { app: 'calendar', type: 'calendar', ts: startIso, agent: 'calendar-web', payload };
  try {
    const r = await fetch(`${CALENDAR_URL}/api/events`, { method: 'POST', headers: { ...bearer(tok), 'Content-Type': 'application/json' }, body: JSON.stringify(event) });
    if (!r.ok) return res.status(502).json({ error: 'create_failed', status: r.status });
    // NEVER-TRUST-200: confirm it actually persisted.
    const l = await fetch(`${CALENDAR_URL}/api/events?type=calendar&limit=50`, { headers: bearer(tok) });
    const events = (await l.json()).events || [];
    const created = events.find((e) => (e.payload || {}).title === payload.title && (e.payload || {}).start === payload.start);
    if (!created) return res.status(502).json({ error: 'not_persisted' });
    res.json({ saved: true, event: toUiEvent(created) });
  } catch (e) { console.warn('create', e.message); res.status(502).json({ error: 'calendar_unreachable' }); }
});

app.patch('/api/events/:id', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const tok = await accessTokenFor(req);
  const startIso = toIso(req.body?.start);
  const payload = {
    title: String(req.body?.title || '').trim() || 'Untitled event',
    start: startIso || undefined, end: toIso(req.body?.end) || null,
    all_day: !!req.body?.all_day, location: String(req.body?.location || '').slice(0, 300),
    description: String(req.body?.description || '').slice(0, 4000),
    ...(req.body?.room_id ? { room_id: req.body.room_id, join_url: req.body.join_url } : {}),
  };
  try {
    const r = await fetch(`${CALENDAR_URL}/api/events/${req.params.id}`, {
      method: 'PATCH', headers: { ...bearer(tok), 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, ...(startIso ? { ts: startIso } : {}) }),
    });
    if (r.status === 404) return res.status(404).json({ error: 'not_found' });
    if (!r.ok) return res.status(502).json({ error: 'update_failed' });
    const { event } = await r.json();
    res.json({ saved: true, event: toUiEvent(event) });
  } catch (e) { console.warn('update', e.message); res.status(502).json({ error: 'calendar_unreachable' }); }
});

app.delete('/api/events/:id', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const tok = await accessTokenFor(req);
  try {
    const r = await fetch(`${CALENDAR_URL}/api/events/${req.params.id}`, { method: 'DELETE', headers: bearer(tok) });
    if (!r.ok && r.status !== 404) return res.status(502).json({ error: 'delete_failed' });
    res.json({ deleted: true });
  } catch (e) { res.status(502).json({ error: 'calendar_unreachable' }); }
});

app.get('/healthz', (req, res) => res.json({ ok: true, calendar: CALENDAR_URL }));
app.use(express.static('public'));
app.get('*', (req, res, next) => { if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) return next(); res.sendFile('index.html', { root: 'public' }); });
app.listen(PORT, () => console.log(`mikeos-calendar-web on :${PORT} (client ${CLIENT_ID}, calendar ${CALENDAR_URL})`));
