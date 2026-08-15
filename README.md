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
- **Channel health sweep**: cron `*/10 * * * *` chủ động probe batch kênh nhỏ (ưu tiên chưa check), đánh dấu `channel_health` online/offline/unknown → lộ ra qua `/api/admin/offline` + `health_status` ở `/api/admin/channels`. Bắt cả link "200 + HTML lỗi". `offline` chỉ khi kênh chết **chắc chắn** (404/410, 5xx, timeout, host không tới được, 200 + không phải HLS); 401/403/429/451 (auth/geo-block/rate-limit) và port không fetch được → `unknown`, không bao giờ gán offline sai.
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
GET    /api/admin/status            # system + playlist status, stats, channel health
GET    /api/admin/channels          # danh sách channel (kèm health_status / last_checked)
GET    /api/admin/categories
POST   /api/admin/sync              # trigger sync (chống concurrent, 409 khi busy)
GET    /api/admin/sync-logs
GET    /api/admin/failures          # kênh lỗi gần đây (log phản ứng khi viewer bật)
DELETE /api/admin/failures/{channelId}   # reset failure state
GET    /api/admin/offline           # kênh đang bị đánh dấu offline (health sweep)
POST   /api/admin/health-check[?limit=N] # chủ động probe một batch kênh ngay
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

### Phát hiện kênh offline (channel health)

Circuit breaker ở proxy chỉ ghi lỗi khi **viewer thực sự bật** vào một kênh chết
(`stream_failures`). Một kênh hỏng link mà chưa ai xem sẽ vẫn hiện "active" trong
playlist mãi. CHRTV bổ sung một **health sweep chủ động**:

- Cron `*/10 * * * *` probe một batch nhỏ (hard cap **12** kênh/lần, xem giải thích
  subrequest bên dưới) kênh active, ưu tiên kênh **chưa được check bao giờ / lâu
  nhất**, xoay vòng đều.
- Mỗi probe fetch upstream (cùng luật SSRF + port-safe như proxy), follow redirect,
  và **xác nhận body thật sự là HLS** — nên link "200 + HTML lỗi" cũng bị đánh
  offline, không chỉ 4xx/5xx/timeout.
- **Chỉ kết luận `offline` khi kênh chết chắc chắn**: 404/410, 5xx, timeout, host
  không tới được, hoặc 200 + body không phải HLS. Các trường hợp phụ thuộc vị trí
  probe — 401/403/429/451 (auth / geo-block / rate-limit), port Worker không fetch
  được (vd `:30113`, player tự phát trực tiếp) — đánh dấu `unknown` kèm `error_code`,
  **không** bao giờ tính là offline. Cron trigger chạy ở **colo ngẫu nhiên** của
  Cloudflare (có thể ngoài lãnh thổ VN), nên một kênh geo-block nước ngoài vẫn
  hoàn toàn xem được với viewer trong nước — gán offline cho nó là sai.
- Kết quả lưu vào bảng `channel_health` (state mới nhất mỗi kênh) và lộ ra qua
  `GET /api/admin/offline`, `health_status` trong `/api/admin/channels`, và
  `health` summary trong `/api/admin/status`.

> **Vì sao batch bị giới hạn 12 kênh?** Mỗi probe tốn 1 subrequest + tối đa 3 lần
> follow redirect. Gói Free của Workers chỉ cho **50 subrequest mỗi invocation** —
> vượt quá, mọi `fetch` phía sau đều ném lỗi mạng và toàn bộ kênh được quét trong
> phần dư bị **gán offline oan**. Batch 12 × tối đa 4 fetch = 48 < 50 là an toàn.
> Trả phí (1.000 subrequest) thì có thể nâng `MAX_PROBES_PER_RUN` lên.

Chạy sweep ngay (vd để quét toàn bộ kênh lần đầu sau deploy — gọi lặp lại vài lần,
mỗi lần quét 12 kênh tiếp theo trong vòng xoay):

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://YOUR_DOMAIN/api/admin/health-check"
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
- `FALLBACK_M3U_URL` — (tuỳ chọn) playlist HLS phát thay khi kênh chết. Cho phép **nhiều URL,
  ngăn cách bằng dấu phẩy**, thử lần lượt:
  1. URL nằm trên port Worker fetch được → CHRTV fetch + re-proxy (segment thành `/seg/{token}`),
     không lộ URL fallback, chạy được cả trên trang https.
  2. URL nằm trên port Worker **không** fetch được (ví dụ `:30113`) → CHRTV **302 redirect thẳng
     player** tới đó. Player trên thiết bị người dùng không bị giới hạn port nên vẫn phát bình thường.
  3. Không có URL nào dùng được → manifest "signal lost" rỗng mặc định.
- `HEALTH_CHECK_BATCH` — (tuỳ chọn) số kênh probe mỗi cron health sweep (`*/10 * * * *`).
  Luôn bị clamp về hard cap 12 (subrequest budget gói Free — xem phần Channel health),
  đặt lớn hơn cũng không quét nhanh hơn mà còn gây gán offline oan.

### ⚠️ Cổng (port) mà Cloudflare Workers fetch được

Worker **chỉ** mở subrequest tới các port sau; port khác bị âm thầm đổi về 80/443
hoặc treo tới hết timeout → player báo **"connection is unstable"**:

| Scheme | Port hợp lệ |
|---|---|
| `http:`  | 80, 8080, 8880, 2052, 2082, 2086, 2095 |
| `https:` | 443, 8443, 2053, 2083, 2087, 2096 |

CHRTV kiểm tra trước khi fetch:

- URL kênh trong playlist dùng port không hợp lệ → **trả thẳng URL gốc** cho player (`/tv.m3u`)
  hoặc **302 redirect** (`/live/...`), player tự phát trực tiếp.
- URI trong manifest dùng port không hợp lệ → **không rewrite**, không proxy.
- `FALLBACK_M3U_URL` dùng port không hợp lệ (ví dụ `:30113`) → **302 redirect player** tới URL đó
  thay vì treo timeout hoặc im lặng trả manifest rỗng.

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
username/password nào cũng được (kể cả để trống), vì playlist vốn đã mở.
Nếu username trùng user có trong D1 thì vẫn phải đúng mật khẩu.
Đặt `PUBLIC_PLAYLIST="false"` để bắt buộc tài khoản thật.

CHRTV đọc thông tin đăng nhập từ **mọi cách client gửi**: query string,
form POST, **JSON POST** (IPTV Smarters) và **HTTP Basic auth**.

Endpoint được hỗ trợ:

| Route | Dùng bởi |
|---|---|
| `/player_api.php`, `/player-api.php`, `/playerapi.php` | TiviMate, Smarters, OTT Navigator |
| `/panel_api.php` | client cũ (trả nguyên `available_channels` + `categories`) |
| `/get.php`, `/enigma2.php` | tải M3U |
| `/live/{u}/{p}/{id}`, `/{u}/{p}/{id}` | phát kênh (dạng có và không có tiền tố `/live`) |

Cấu hình trong player:

```
Server / Portal URL : https://YOUR_DOMAIN     (không thêm /get.php, không thêm port)
Username            : bất kỳ
Password            : bất kỳ
```

## Development & test

```bash
npm run dev        # wrangler dev (cần .dev.vars, xem .dev.vars.example)
npm test           # 110 tests (unit + integration, chạy trong workerd)
npm run typecheck
npm run build      # wrangler deploy --dry-run
```

## Playlist

Sửa `playlists/tv.m3u`, commit lên `main` — cron sẽ tự sync trong ≤15 phút,
hoặc `POST /api/admin/sync` để sync ngay.

## License

MIT
