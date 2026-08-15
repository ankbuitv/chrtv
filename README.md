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
- `FALLBACK_M3U_URL` — (tuỳ chọn) playlist HLS phát thay khi kênh chết; CHRTV fetch + re-proxy
  (segment thành `/seg/{token}`) nên player phát bình thường, không lộ URL fallback. Để trống
  thì dùng manifest "signal lost" rỗng mặc định.

### ⚠️ Cổng (port) mà Cloudflare Workers fetch được

Worker **chỉ** mở subrequest tới các port sau; port khác bị âm thầm đổi về 80/443
hoặc treo tới hết timeout → player báo **"connection is unstable"**:

| Scheme | Port hợp lệ |
|---|---|
| `http:`  | 80, 8080, 8880, 2052, 2082, 2086, 2095 |
| `https:` | 443, 8443, 2053, 2083, 2087, 2096 |

CHRTV kiểm tra trước khi fetch:

- URL kênh trong playlist dùng port không hợp lệ → **bị loại khi sync** (không đưa vào D1).
- URI trong manifest dùng port không hợp lệ → **không rewrite**, không proxy.
- `FALLBACK_M3U_URL` dùng port không hợp lệ (ví dụ `:30113`) → dùng ngay manifest
  "signal lost" có sẵn thay vì treo timeout ở mọi request kênh chết.

### Chống "connection is unstable"

- **Token ổn định**: cùng một segment/kênh luôn ra cùng một URL trong cửa sổ 10 phút
  (IV suy ra bằng HMAC thay vì random) → player tái sử dụng buffer, không tải lại
  toàn bộ segment mỗi lần refresh manifest.
- **Timeout tách biệt**: manifest 8s (live phải nhanh), segment 20s.
- **Retry 1 lần** cho lỗi tạm thời (timeout / mạng / 5xx) trước khi mở circuit breaker.
- **SEGMENT_TTL 60 phút** (trước là 15) → token không hết hạn giữa chừng khi đang xem.
- **Không forward `accept-encoding`**, ép `identity` → body không bị giải nén lệch
  `Content-Length` làm player thấy segment cụt.

### Xtream Codes

Khi `PUBLIC_PLAYLIST="true"`, client Xtream đăng nhập bằng **bất kỳ**
username/password nào cũng được (`/get.php`, `/player_api.php`, `/live/...`),
vì playlist vốn đã mở. Nếu username trùng user có trong D1 thì vẫn phải đúng
mật khẩu. Đặt `PUBLIC_PLAYLIST="false"` để bắt buộc tài khoản thật.

Cấu hình trong player:

```
Server / Portal URL : https://YOUR_DOMAIN     (không thêm /get.php, không thêm port)
Username            : bất kỳ
Password            : bất kỳ
```

## Development & test

```bash
npm run dev        # wrangler dev (cần .dev.vars, xem .dev.vars.example)
npm test           # 80 tests (unit + integration, chạy trong workerd)
npm run typecheck
npm run build      # wrangler deploy --dry-run
```

## Playlist

Sửa `playlists/tv.m3u`, commit lên `main` — cron sẽ tự sync trong ≤15 phút,
hoặc `POST /api/admin/sync` để sync ngay.

## License

MIT
