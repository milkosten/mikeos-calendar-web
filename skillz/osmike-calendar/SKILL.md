---
name: osmike-calendar
description: Use when a person asks to read their OsMike calendar events, appointments, or meeting links.
---

Use OsMike Connect to read the calling agent's person's own calendar. Authentication is automatic through `osmike_person`; no API key or browser login is needed.

Examples:

```sh
osmike-int osmike-calendar test
osmike-int osmike-calendar me
osmike-int osmike-calendar events --limit 20
osmike-int osmike-calendar events --limit 1000
```

`me` is a cheap identity check. `events` returns event IDs, titles, start/end, all-day status, location, description, and meeting links when present. Filter the returned dates locally when answering questions about a time period. The limit is 1–1000 (default 1000); the response is bounded and may not include the person's complete calendar. Do not assume backend ordering or invent missing events.

Agent access requires `calendar:read` and is read only: creating, editing, and deleting events return 403. There is no parameter to select another person. Never request or expose bearer tokens. Do not send mail or claim that an event has been changed.
