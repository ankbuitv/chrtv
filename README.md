<div align="center">

# 📺 CHRTV

**Cloud IPTV Gateway — Cloudflare Workers + D1**

Playlist M3U trong repo GitHub này là *source of truth*. CHRTV tự động sync vào D1,
phát playlist đã tokenize cho IPTV player, proxy HLS, và tự sinh HLS fallback khi kênh chết.

</div>

---

## Người dùng cuối chỉ cần một URL

```
https://YOUR_DOMAIN/tv.m3u
```

Dán URL trên vào VLC / TiviMate / IPTV Smarters / OTT Navigator / Kodi — xong.
Không cần key, không cần token, không cần cấu hình gì thêm.
(`/xem.m3u` là alias tương đương.)

## Kiến trúc

```
GitHub M3U (playlists/tv.m3u)
      │  Cron 15 phút / Admin trigger
      ▼
 sync: fetch → hash check → parse → validate → normalize
      ▼
 Cloudflare D1 (channels, categories, users, keys, devices, logs)
      ▼
 /tv.m3u   /player_api.php   /get.php   /live/{u}/{p}/{id}   /xmltv.php
      ▼
 /hls/{token}.m3u8  ── rewrite manifest, re-tokenize mọi URI
 /seg/{token}.ts    ── stream passthrough (Range/206, không buffer)
      ▼
 upstream chết? → HLS error manifest hợp lệ (không bao giờ trả HTML cho player)
```

- **Token**: AES-256-GCM, chứa upstream URL + iat/exp, tamper-proof, tự hết hạn. Upstream URL không bao giờ lộ ra ngoài.
- **SSRF guard**: chỉ http/https public; chặn localhost, private IP, link-local, metadata endpoints — kiểm tra cả từng hop redirect.
- **Circuit breaker**: upstream fail → failure state TTL 30s trong Cloudflare Cache; trong TTL trả ngay fallback manifest, hết TTL tự retry.
- **Playlist sync an toàn**: playlist mới lỗi → giữ nguyên version cũ, đánh dấu sync failed. Hash không đổi → không ghi lại DB.

## Routes

| Route | Mô tả |
|---|---|
| `GET /` | Landing page (dark, minimal) |
| `GET /tv.m3u`, `/xem.m3u` | Playlist chính (tuỳ chọn `?key=chr_…&mac=AA:BB:…`) |
| `GET /hls/{token}.m3u8` | HLS manifest proxy (rewrite + re-tokenize) |
| `GET /seg/{token}[.ext]` | Media passthrough (ts/m4s/aac/mp4/key/vtt) |
| `GET /player_api.php` | Xtream Codes API (`get_live_categories`, `get_live_streams`, …) |
| `GET /get.php` | Xtream M3U download |
| `GET /live/{user}/{pass}/{id}.m3u8` | Xtream live stream |
| `GET /xmltv.php`, `/epg.xml` | XMLTV EPG (cache 30′, fallback minimal hợp lệ) |
| `* /api/admin/*` | Admin API (Bearer `ADMIN_TOKEN`) |
| `GET /healthz` | Health check |
| còn lại | 404 “Signal Lost” |

### Admin API

`Authorization: Bearer $ADMIN_TOKEN`

```
GET    /api/admin/status            # system + playlist status, stats
GET    /api/admin/channels          # danh sách channel
GET    /api/admin/categories
POST   /api/admin/sync              # trigger sync (chống concurrent, 409 khi busy)
GET    /api/admin/sync-logs
GET    /api/admin/failures          # kênh lỗi gần đây
DELETE /api/admin/failures/{channelId}   # reset failure state
GET    /api/admin/users             # không bao giờ trả password hash
POST   /api/admin/users             # {username, password, expires_at?}
PATCH  /api/admin/users/{id}        # {status: active|disabled|expired|revoked}
DELETE /api/admin/users/{id}        # revoke
GET    /api/admin/keys
POST   /api/admin/keys              # trả raw key đúng MỘT lần: chr_…
PATCH  /api/admin/keys/{id}
DELETE /api/admin/keys/{id}
GET    /api/admin/devices
GET    /api/admin/devices/mac/{mac}
PATCH  /api/admin/devices/{id}
DELETE /api/admin/devices/{id}
```

## Deploy

```bash
npm install

# 1. Tạo D1 database, điền database_id vào wrangler.toml
npx wrangler d1 create chrtv-db

# 2. Chạy migrations
npm run db:migrate          # remote
npm run db:migrate:local    # local dev

# 3. Secrets
npx wrangler secret put SECRET_KEY    # 32+ ký tự ngẫu nhiên
npx wrangler secret put ADMIN_TOKEN   # bearer token cho admin API

# 4. Deploy (cron triggers tự đăng ký từ wrangler.toml)
npm run deploy

# 5. Sync playlist lần đầu
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://YOUR_DOMAIN/api/admin/sync
```

Cấu hình trong `wrangler.toml`:

- `PLAYLIST_URL` — raw URL của `playlists/tv.m3u` trong repo này
- `EPG_URL` — nguồn XMLTV (tuỳ chọn)
- `PUBLIC_PLAYLIST` — `"true"` (mặc định): `/tv.m3u` mở tự do; `"false"`: bắt buộc `?key=`

## Development & test

```bash
npm run dev        # wrangler dev (cần .dev.vars, xem .dev.vars.example)
npm test           # 68 tests (unit + integration, chạy trong workerd)
npm run typecheck
npm run build      # wrangler deploy --dry-run
```

## Playlist

Sửa `playlists/tv.m3u`, commit lên `main` — cron sẽ tự sync trong ≤15 phút,
hoặc `POST /api/admin/sync` để sync ngay.

## License

MIT
