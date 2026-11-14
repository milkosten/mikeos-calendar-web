# mikeos-calendar-web — calendar.osmike.com

The human-facing **MikeCalendar** UI. Month + agenda views, create/edit/delete
events, all stored in the MikeOS-native calendar backend (`mikeos-events` @
`calendar-api.osmike.com`) using the signed-in user's account.osmike.com Bearer
token (dual-auth). Meetings scheduled in **meetings.osmike.com** appear here
automatically (they are `type:"calendar"` events with a `room_id` + `join_url`, so
they render with a **Join** button). Sign in with a MikeOS Account (OAuth2
Auth-Code + PKCE). Zero Google — MikeCalendar is the default; a Google Calendar
connect is an optional feature of the native MikeTime app, not this UI.

## Deploy (242)
`./deploy.sh` — one container `mikeos-calendar` (:8096, deploy_default), Caddy
`calendar.osmike.com`. Needs `.env` with `COOKIE_SECRET`.

## API (proxies to the calendar backend, forwarding the user's Bearer)
`GET/POST /api/events`, `PATCH/DELETE /api/events/:id`, `/api/me`, `/auth/*`.

### Read-only agent access

`/api/me` and `/api/events?limit=1..1000` accept account.osmike.com RS256
agent bearer tokens (issuer `https://account.osmike.com`, audience
`account.osmike.com`, `act.iss=a2a`, nonempty `act.sub`, scope `calendar:read`).
The server verifies signatures with the account's fixed `/oauth/jwks.json`
endpoint, caches keys for five minutes, and forwards the original verified token
to the events backend, whose database queries are scoped to the person in `sub`.
Agent mutations under `/api` return 403, including when a browser session cookie
is also present. Invalid bearer credentials never fall back to a browser session.
Browser session authentication remains available for the UI.

Connect specification: `connect/osmike-calendar.json`.
Agent skill: `skillz/osmike-calendar/SKILL.md`.
The supervisor reviews and publishes these artifacts. Run `npm test` for the
signature, claims, person identity, scope and read-only authorization checks.
