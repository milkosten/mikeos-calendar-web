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
