<div align="center">

# 📺 CHRTV

**Cloud IPTV Gateway — Cloudflare Workers + D1**

The M3U playlist in this GitHub repository is the *source of truth*. CHRTV
automatically syncs it into D1, serves a tokenized playlist to IPTV players,
proxies HLS, and auto-generates a safe HLS fallback when a channel goes down.

</div>

---

> **Language:** [English](README.md) · [Tiếng Việt](README.vi.md)

## End users only need one URL

```
https://YOUR_DOMAIN/tv.m3u
```

Paste that URL into VLC / TiviMate / IPTV Smarters / OTT Navigator / Kodi —
done. No key, no token, no extra configuration required.
(`/xem.m3u` is an equivalent alias.)

## Architecture

```
GitHub M3U (playlists/tv.m3u)
      │  15-minute cron / admin trigger
      ▼
 sync: fetch → hash check → parse → validate → normalize
      ▼
 Cloudflare D1 (channels, categories, users, sessions, keys, devices, auth logs)
      ▼
 /tv.m3u   POST /api/login → /p/{session}.m3u   /lg/{u}?{p}.m3u   Xtream API
      ▼
 /epg/{token}.xml   ── dedicated EPG token, bound to the same identity
 /hls/{token}.m3u8  ── manifest rewrite, every URI re-tokenized
 /seg/{token}.ts    ── segment/key/subtitle passthrough (Range/206, no buffering)
      ▼
 upstream dead? → valid HLS error manifest (HTML is never served to players)
```

- **Tokens**: AES-256-GCM, carrying the upstream URL + iat/exp plus the
  authenticated identity (`MAC`, `user_id`, `access_key_id`, `session_id` when
  present), tamper-proof, self-expiring. Child tokens inside a manifest inherit
  the same identity. User/key/session state is re-checked on every manifest/EPG
  load, so a revoke takes effect before the worker ever touches the upstream.
  Upstream URLs never appear in the playlist.
- **SSRF guard**: only public http(s); localhost, private IPs, link-local and
  metadata endpoints are blocked — including on every redirect hop.
- **Circuit breaker**: upstream failure → 30s failure state in the Cloudflare
  cache; within the TTL the fallback manifest is served immediately, after the
  TTL it retries automatically.
- **Channel health sweep**: cron `*/10 * * * *` proactively probes a small batch
  of channels (oldest-checked first) and marks `channel_health`
  online/offline/unknown → surfaced via `/api/admin/offline` +
  `health_status` in `/api/admin/channels`. `offline` is **only set when a link
  is truly unreachable** (host unreachable, **silent for more than 30s**,
  404/410) and must fail that way for **2 consecutive probes** before being
  confirmed. Every case where the server still answers — 5xx,
  401/403/429/451 (auth/geo-block/rate-limit), 200 + non-HLS body
  (anti-bot page) — is `unknown`, never falsely flagged offline.
- **Safe playlist sync**: a broken new playlist keeps the previous version and
  marks the sync failed. Unchanged hash → no DB writes.
- **Safe session login**: `POST /api/login` exchanges username/password for a
  `/p/{opaque-token}.m3u` URL with no password in it. The server only stores an
  HMAC of the token; a session lives until `users.expires_at` or until the
  user/session is revoked, and it honours `max_connections` with optional
  oldest-session replacement.
- **Authentication audit**: logins, M3U downloads and access-key/Xtream usage
  are durably written to `auth_events`, including user/session, outcome,
  user-agent and the **raw IP observed by Cloudflare** for operational needs;
  auto-purged after 30 days.
- **Honeypot + scanner bans**: obvious vulnerability probes (`/.env`,
  `/.git/*`, `/wp-login.php`, `/phpmyadmin/*`) get a fake 404 and ban the
  observed edge IP for 24 hours. Ban tables keep only HMAC-SHA256 of the IP.
  Cross-site requests (browser-declared `Sec-Fetch-Site: cross-site`) still get
  the fake 404 but never create a ban, so a malicious link/embed from another
  site cannot get the victim banned. Direct scanners (no Fetch Metadata) are
  still banned. Common IPTV app probes (`/portal.php`, Stalker, Xtream) are
  not traps.
- **Brute-force-proof private login**: `/lg/{username}?{password}.m3u` always
  authenticates a D1 user even while the public playlist is on. Five failures
  in 10 minutes from the same IP create a 24-hour ban; the counter is durable
  across Cloudflare colos.

## Routes

| Route | Description |
|---|---|
| `GET /` | Landing page (dark, minimal; doesn't advertise the public playlist URL) |
| `GET /login` | User portal: log in, copy M3U, view/revoke sessions & devices |
| `GET /admin` | Security dashboard: users, sessions, audit, bans, keys/devices, health/sync |
| `GET /tv.m3u`, `/xem.m3u` | Main public playlist (optional `?key=chr_…&mac=AA:BB:…`; tokens bind MAC/key/user) |
| `POST /api/login` | Exchange D1 credentials for an opaque session + `/p/{token}.m3u` URL |
| `GET /api/account/sessions` | List the current user's sessions (Bearer session token) |
| `DELETE /api/account/sessions/{id}` | Revoke one of the current user's sessions |
| `GET /p/{session}.m3u` | Session playlist with no username/password in the URL |
| `GET /lg/{username}?{password}.m3u` | Legacy private playlist; requires D1 user/password, tokens bound to user |
| `GET /epg/{token}.xml` | XMLTV via a dedicated EPG token with expiry/identity binding |
| `GET /hls/{token}.m3u8` | HLS manifest proxy (rewrite + re-tokenize every child URI) |
| `GET /seg/{token}[.ext]` | Media passthrough (ts/m4s/aac/mp4/key/vtt/subtitle) |
| `GET /player_api.php` | Xtream Codes API; always requires a real D1 user |
| `GET /get.php` | Xtream M3U; always requires a real D1 user |
| `GET /live/{user}/{pass}/{id}.m3u8` | Exchange Xtream credentials for a redirect to the opaque live URL |
| `GET /xmltv.php`, `/epg.xml` | Exchange Xtream credentials for a redirect to the tokenized EPG |
| `* /api/admin/*` | Admin API (Bearer `ADMIN_TOKEN`) |
| `GET /healthz` | Health check |
| anything else | 404 “Signal Lost” |

### Admin API

`Authorization: Bearer $ADMIN_TOKEN`

```
GET    /api/admin/status            # system + playlist status, stats, channel health
GET    /api/admin/channels          # channel list (with health_status / last_checked)
GET    /api/admin/categories
POST   /api/admin/sync              # trigger sync (concurrency-safe, 409 when busy)
GET    /api/admin/sync-logs
GET    /api/admin/failures          # recent channel failures (reaction log when viewers hit them)
DELETE /api/admin/failures/{channelId}   # reset failure state
GET    /api/admin/security-bans     # active bans; IP hashes only, never raw IPs
DELETE /api/admin/security-bans/{ipHash} # lift a ban (propagates globally within ≤60s)
GET    /api/admin/auth-events[?limit=N]  # login/M3U/Xtream/access-key audit with raw IPs
GET    /api/admin/sessions          # user sessions/devices, first/last IP, status
DELETE /api/admin/sessions/{id}     # revoke any session
GET    /api/admin/offline           # channels currently flagged offline (health sweep)
POST   /api/admin/health-check[?limit=N] # proactively probe a batch of channels now
GET    /api/admin/users             # never returns password hashes
POST   /api/admin/users             # {username, password, expires_at?, max_connections?}
PATCH  /api/admin/users/{id}        # {status?, expires_at?, max_connections: 1..100}
DELETE /api/admin/users/{id}        # mark user revoked and revoke active sessions
GET    /api/admin/keys
POST   /api/admin/keys              # {label?, max_devices?, user_id?}; returns the raw key exactly ONCE
PATCH  /api/admin/keys/{id}         # {status?} and/or {user_id: number|null}
DELETE /api/admin/keys/{id}
GET    /api/admin/devices
GET    /api/admin/devices/mac/{mac}
PATCH  /api/admin/devices/{id}
DELETE /api/admin/devices/{id}
```

The dashboard at `https://YOUR_DOMAIN/admin` calls those same-origin APIs. Enter
`ADMIN_TOKEN` in the browser; the token stays in `sessionStorage` and is never
embedded in the HTML/source. The dashboard supports user/expiry/connection
limits, session revoke, ban/unban, login audit with raw IPs, access
keys/devices, health check and playlist sync. Because the audit contains
personal data (raw IPs), only grant `ADMIN_TOKEN` to operators and keep the
default 30-day retention.

### Secure login and session/device management

Open `https://YOUR_DOMAIN/login`, or call the API directly:

```bash
curl -X POST https://YOUR_DOMAIN/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ken","password":"use-a-strong-password","device_name":"Living room TV"}'
```

A `201` returns `access_token`, a `playlist_url` of the form
`https://YOUR_DOMAIN/p/{opaque-token}.m3u` and session metadata. The M3U URL
contains no username/password; D1 only stores `HMAC-SHA256(token)` and a
non-secret prefix, never the raw token. Login/account/playlist responses are
always `private, no-store` with `Referrer-Policy: no-referrer`.

- Sessions have no separate 30-day TTL: their limit is `users.expires_at` (or
  unlimited when the account has none). The playlist uses the earlier of the
  stored session expiry and the current account expiry; media/EPG and every
  child HLS token never exceed that point. Each manifest/EPG load re-checks D1,
  so revoked, disabled, expired or deleted sessions/users stop before the worker
  calls the upstream.
- `max_connections` (1–100) limits the number of active sessions. When full,
  the API returns `409 SESSION_LIMIT`; send `"replace_oldest": true` to revoke
  the least recently used session and create a new one.
- `GET /api/account/sessions` with `Authorization: Bearer {access_token}` lists
  only that user's devices/sessions; `DELETE /api/account/sessions/{id}` can
  only revoke a session owned by the same user. Admins can view/revoke
  everything at `/admin`.
- The portal keeps the bearer token in browser `sessionStorage`, never embeds
  secrets in HTML and never puts the password in a URL. For IPTV players that
  can't POST, log in once on the portal and copy `playlist_url`.

Example — list sessions:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://YOUR_DOMAIN/api/account/sessions
```

### Legacy private playlist via `/lg`

Create a D1 user through the Admin API (password at least 8 characters), then
use a URL of the form:

```text
https://YOUR_DOMAIN/lg/ken?use-a-strong-password.m3u
```

Everything after `?` up to the `.m3u` suffix is the password — **not** a
`password=...` query. Usernames/passwords with reserved characters must be
percent-encoded. This route never accepts guests: it always authenticates a D1
user and checks status/expiry, even when `PUBLIC_PLAYLIST="true"`. The returned
M3U only contains opaque tokens bound to the authenticated `user_id` (and the
other claims enabled by `TOKEN_BINDING`). Responses are `private, no-store`
with no referrer; CHRTV never logs the query/password.

Wrong credentials return the same `AUTH_INVALID` so existing usernames cannot
be enumerated. The brute-force counter is stored as an IP hash in D1:
**5 failures / 10 minutes** bans the IP for a day. The 5th attempt returns
`429`; later requests return `403 SECURITY_BANNED` until the ban expires or an
admin calls `DELETE /api/admin/security-bans/{ipHash}`.

> By design, the credential sits in the URL, so it may show up in the access
> logs of infrastructure in front of the worker. Always use HTTPS, a strong
> dedicated password, and limit URL sharing.

### Token binding — MAC / user ID / access key

On every M3U response, CHRTV builds an identity binding from the observed edge
address, the authenticated credential and the client-declared device label.
Claims are enabled with `TOKEN_BINDING` (**default `"mac,user,key"`**):

- `mac`: taken from `?mac=`, normalized to `AA:BB:CC:DD:EE:FF`, and registers a
  device when the playlist is used with an access key. MACs, IPs and IDs live
  **inside the AES-GCM payload**, never as plaintext in the URL.
- `user_id`: taken from the D1 user logged in via Xtream, or from an access key
  linked to a user via `user_id`. Clients can't declare `user_id` themselves.
- `access_key_id`: attached automatically when using `?key=chr_…`, so even two
  keys behind the same IP/MAC get different tokens.
- `session_id`: always attached together with its owner `user_id` to playlists
  from `/p/{session}.m3u`, even when the operator sets `TOKEN_BINDING=none`;
  it's a revoke capability, not an optional client-declared claim.
- `ip`: **disabled by default** (see below); when enabled, it's taken only from
  the trusted edge header `CF-Connecting-IP` (never `X-Forwarded-For`) and every
  `/hls` and `/seg` request must come from that exact IP or gets
  `403 TOKEN_BINDING_MISMATCH` before touching the upstream.

> **Why `ip` is no longer the default:** binding tokens to the playlist-fetching
> IP breaks playback whenever the viewing IP differs from the login/playlist IP
> — logging in on a PC and playing on a TV box, or ISPs that rotate public IPs
> (CGNAT is very common in Vietnam). That surfaced as `403 TOKEN_BINDING_MISMATCH`
> and "stream won't play" even with valid credentials. Tokens are still bound to
> the D1 user/session (`uid`/`sid`) and access key, so revoking a user or session
> still kills their streams instantly. Re-add `ip` if you want the strictest
> anti-sharing posture and always fetch + play from the same network.

Manifest/segment tokens minted afterwards inherit the full binding above. The
playlist also points `url-tvg`/`x-tvg-url` at `/epg/{token}.xml`; the EPG token
has its own kind, so a manifest/segment token can't be substituted there. Child
URIs in HLS — child manifests, segments, encryption keys, init maps and
subtitles — must all be rewritten into tokens; if a URI is unsafe or cannot be
tokenized, CHRTV fails closed with a safe fallback HLS instead of leaking the
upstream URL.

Tokens stay stable for a 10-minute window **for the same identity**, but differ
across MAC/user/key. Playlist requests made with a linked access key are also
rejected when the owner user is disabled, revoked or expired. Create a
user-linked access key with:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"Living room TV","user_id":12,"max_devices":2}' \
  https://YOUR_DOMAIN/api/admin/keys
```

> A hardware MAC is layer-2 information that an HTTP server on the internet
> can't read by itself. MAC here is therefore a client-declared device identity,
> tied to the access key and used to personalize tokens/limit devices; the real
> credential remains the access key.

### Offline channel detection (channel health)

The proxy circuit breaker only records failures when a **viewer actually tunes
into** a dead channel (`stream_failures`). A channel with a broken link that
nobody watches would stay "active" in the playlist forever. CHRTV adds a
**proactive health sweep**:

- Cron `*/10 * * * *` probes a small batch (hard cap **12** channels/run — see
  the subrequest explanation below) of active channels, prioritizing channels
  **never checked / checked longest ago**, rotating evenly.
- Each probe fetches the upstream (same SSRF + port-safe rules as the proxy),
  follows redirects and verifies the body actually looks like HLS.
- **Probes wait up to 30s** (one total budget for the whole redirect chain)
  before declaring a timeout: slow relays like devda.undo.it bouncing to a CDN
  take 10–25s to first byte — slow to tune in but perfectly watchable. Short
  timeouts (6–8s) used to wrongly flag exactly these channels as offline on
  every sweep.
- **`offline` is reserved for links that are truly UNREACHABLE**: host
  unreachable (dead DNS / connection refused), silence for more than 30s, or
  404/410 (link no longer exists). If the server still answers — 5xx
  (overloaded/restarting), 401/403/429/451 (auth/geo-block/rate-limit), or
  200 with a non-HLS body (usually an anti-bot page only shown to datacenter
  probes while real players still work) — the link **is reachable**, mark
  `unknown` with the `error_code`, and **never** call it offline. Cron triggers
  run at a **random Cloudflare colo** (possibly outside Vietnam), so a
  geo-blocked channel for foreign viewers can still be perfectly watchable for
  domestic viewers — flagging it offline would be wrong.
- **Two consecutive failed probes are required before flagging offline**
  (`fail_streak` in `channel_health`): a single failure might just be a bad
  network tick at the colo running the cron. The first failure records
  `unknown` (keeping `error_code` so admins see suspicious channels); only the
  second consecutive one flips to `offline`. A successful or inconclusive probe
  resets the streak to 0, so flaky channels are never wrongly reported offline.
- Results live in the `channel_health` table (one row per channel, latest
  state) and are surfaced via `GET /api/admin/offline`, `health_status` in
  `/api/admin/channels`, and the `health` summary in `/api/admin/status`.

> **Why is the batch capped at 12?** Each probe costs 1 subrequest + up to 3
> redirect follows. The Workers Free plan allows only **50 subrequests per
> invocation** — beyond that every later `fetch` throws a network error and all
> channels scanned in the remainder get **falsely flagged offline**. Batch 12 ×
> max 4 fetches = 48 < 50 is safe. On a paid plan (1,000 subrequests) you can
> raise `MAX_PROBES_PER_RUN`.

Run a sweep right now (e.g. to scan the whole catalog right after deploy —
call it repeatedly, each call sweeps the next 12 channels in rotation):

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://YOUR_DOMAIN/api/admin/health-check"
```

## Deploy

```bash
npm install

# 1. Create the D1 database and fill in database_id in wrangler.toml
npx wrangler d1 create chrtv-db

# 2. Run migrations (includes 0005 token identity, 0006 bans, 0007 sessions/audit)
npm run db:migrate          # remote
npm run db:migrate:local    # local dev

# 3. Secrets
npx wrangler secret put SECRET_KEY    # 32+ random characters
npx wrangler secret put ADMIN_TOKEN   # bearer token for the admin API

# 4. Deploy (cron triggers auto-register from wrangler.toml)
npm run deploy

# 5. First playlist sync
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://YOUR_DOMAIN/api/admin/sync
```

Configuration in `wrangler.toml`:

- `PLAYLIST_URL` — raw URL of `playlists/tv.m3u` in this repository
- `EPG_URL` — upstream XMLTV source (optional); never exposed to clients, the
  playlist only receives `/epg/{token}.xml`
- `PUBLIC_PLAYLIST` — `"true"` (default): only `/tv.m3u`/`xem.m3u` are open;
  `"false"`: `?key=` is required. This variable does **not** allow Xtream or
  login with arbitrary credentials; those endpoints always authenticate a real
  D1 user
- `TOKEN_BINDING` — comma-separated claim list: `ip`, `mac`, `user`, `key`.
  Default `"mac,user,key"`; pick any subset, e.g. `"ip,user"` or
  `"mac,user,key"`. `"none"` disables deliberate identity binding. Invalid
  values fail safe to the full secure default rather than silently disabling
  protection
- `HONEYPOT_ENABLED` — default `"true"`; set `"false"` only to disable scanner
  trap detection. Existing bans and brute-force protection still apply.
- `HONEYPOT_BAN_SECONDS` — honeypot/brute-force ban duration, default `86400`
  (one day), minimum 60 seconds, clamped to a maximum of 7 days.
- `REDIRECT_UNSUPPORTED_PORTS` — default `"true"`: an upstream on a port
  Workers cannot fetch (e.g. DuckDNS on `:30113`) is served to the player as a
  **302 redirect to the origin** instead of being skipped — players are
  ordinary clients and can open any port, so the channel keeps playing even
  though the Worker can't proxy it. Set `"false"` for strict origin hiding
  (such channels fall back / fail closed and the origin is never disclosed).
- `FALLBACK_M3U_URL` — (optional) HLS playlist served when a channel is dead.
  Supports **multiple comma-separated URLs**, tried in order:
  1. URL on a worker-fetchable port → CHRTV fetches and re-proxies it (segments
     become `/seg/{token}`), never exposing the fallback URL, works on https
     pages too.
  2. URL on a port the worker **cannot** fetch (e.g. `:30113`) → with
     `REDIRECT_UNSUPPORTED_PORTS=true` it is served as a 302 redirect to its
     origin; with `"false"` it is skipped and clients are never redirected to
     the raw origin.
  3. No usable URL → the default empty "signal lost" manifest.
- `HEALTH_CHECK_BATCH` — (optional) channels probed per cron health sweep
  (`*/10 * * * *`). Always clamped to the hard cap of 12 (Free-plan subrequest
  budget — see Channel health); setting it higher doesn't sweep faster and can
  cause false offline flags.

### ⚠️ Ports Cloudflare Workers can fetch

The worker **only** opens subrequests to these ports; any other port is
silently rewritten to 80/443 or hangs until the timeout → players report
**"connection is unstable"**:

| Scheme | Valid ports |
|---|---|
| `http:`  | 80, 8080, 8880, 2052, 2082, 2086, 2095 |
| `https:` | 443, 8443, 2053, 2083, 2087, 2096 |

CHRTV validates before fetching. With `REDIRECT_UNSUPPORTED_PORTS=true`
(default), a source on an unfetchable port keeps working via a **direct 302
redirect to the origin** — the player (an ordinary client) can open any port,
so it tunes in straight from the source:

- A channel URL on an invalid port only appears in the playlist as
  `/hls/{token}` (opaque). After token + identity binding checks, the worker
  answers with `302 Location: <origin>` and the player connects directly. No
  fallback fetch, no dead manifest.
- A child URI inside a fetched manifest on an invalid port is left as its raw
  origin URL in the rewritten manifest (only that URI bypasses the proxy —
  fetchable siblings stay tokenized `/hls/` + `/seg/`).
- `FALLBACK_M3U_URL` on an invalid port (e.g. `:30113`) → served as a 302
  redirect to that origin.

With `REDIRECT_UNSUPPORTED_PORTS=false`, **strict origin hiding** applies
instead: invalid-port channels fail over to a proxyable fallback / the "signal
lost" manifest, invalid-port child URIs reject the whole manifest, and
invalid-port fallback candidates are skipped — the origin is never disclosed in
any response.

Keep in mind a redirected stream bypasses the CHRTV proxy: the player talks to
the origin directly, so CHRTV can't re-rewrite child URIs, cache segments, or
hide that origin from viewers of that channel. For fully proxied playback,
custom-port sources should still sit behind **HTTPS port 443**, a
**Cloudflare Tunnel**, or a **private relay** on a worker-fetchable port.

### Fighting "connection is unstable"

- **Identity-stable tokens**: the same segment/channel + MAC/user/key always
  yields the same URL within the 10-minute window (IV derived with HMAC over
  both seed and payload instead of random); a different identity gets a
  different URL → players reuse their buffer instead of re-downloading every
  segment on each manifest refresh.
- **30s timeout for both manifest and segment**: slow relays
  (devda.undo.it → CDN) taking 10–25s still tune in fine — only when an
  upstream stays **silent for more than 30s** is it declared dead, opening the
  circuit breaker and enabling the fallback.
- **30s is the TOTAL wait budget, not per hop**: the deadline is shared across
  the whole redirect chain *and* the single retry. Previously every redirect
  hop got a fresh 30s, so a slow 6-hop chain could hold a player's spinner for
  up to ~3 minutes before the fallback appeared — now it's at most ~30s, exactly
  as the policy says.
- **30s edge cache for segments**: live segments are immutable once published,
  and segment tokens are deterministic so the same segment always maps to the
  same URL. Only the FIRST request pays the 10–25s slow-relay TTFB; player
  retries, second viewers and ABR-ladder switches get it straight from cache —
  a big drop in "video loading too long" when several people watch at once.
  Manifests are never cached (live playlists change constantly) and Range
  requests go straight upstream.
- **One retry** for fast transient failures (network / 5xx) before the circuit
  breaker opens — but only with whatever is left of the 30s budget. A timeout
  is already conclusive, so it is **not retried** (avoids stretching to 60s
  before the player sees the fallback).
- **SEGMENT_TTL 60 minutes** (was 15) → tokens don't expire mid-viewing.
- **`accept-encoding` is not forwarded**, `identity` is forced → bodies aren't
  decompressed out of sync with `Content-Length`, which used to make players
  see truncated segments.

### Xtream Codes

Xtream **always requires a real active D1 user**, regardless of
`PUBLIC_PLAYLIST`. Wrong/missing credentials never degrade into guest access;
`/tv.m3u` is the only route allowed public by configuration. Successful,
failed and blocked logins are recorded in `auth_events` with the raw client IP
and get the same brute-force ban as the other username/password flows.

CHRTV reads credentials from **every way clients send them**: query string,
form POST, **JSON POST** (IPTV Smarters) and **HTTP Basic auth**.

Supported endpoints:

| Route | Used by |
|---|---|
| `/player_api.php`, `/player-api.php`, `/playerapi.php` | TiviMate, Smarters, OTT Navigator |
| `/panel_api.php` | legacy clients (returns raw `available_channels` + `categories`) |
| `/get.php`, `/enigma2.php` | M3U download |
| `/live/{u}/{p}/{id}`, `/{u}/{p}/{id}` | channel playback (with and without the `/live` prefix) |
| `/xmltv.php`, `/epg.xml` | Xtream EPG with credentials |

`get.php` and the live records in the player API only emit opaque media URLs.
The live route authenticates the credentials, then redirects to
`/hls/{token}.m3u8`; XMLTV authenticates and redirects to `/epg/{token}.xml`.
The password therefore never propagates into child URIs, and the upstream
media/EPG never leaks through API responses.

Player configuration:

```
Server / Portal URL : https://YOUR_DOMAIN     (no /get.php, no port)
Username            : a user created in D1
Password            : that user's correct password
```

## Development & testing

```bash
npm run dev        # wrangler dev (needs .dev.vars, see .dev.vars.example)
npm test           # unit + integration, runs inside workerd
npm run typecheck
npm run build      # wrangler deploy --dry-run
```

## Playlist

Edit `playlists/tv.m3u`, commit to `main` — the cron auto-syncs within ≤15
minutes, or `POST /api/admin/sync` to sync immediately.

## License

MIT
