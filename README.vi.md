<div align="center">

# 📺 CHRTV

**Cloud IPTV Gateway — Cloudflare Workers + D1**

Playlist M3U trong repo GitHub này là *source of truth*. CHRTV tự động sync vào D1,
phát playlist đã tokenize cho IPTV player, proxy HLS, và tự sinh HLS fallback khi kênh chết.

</div>

---

> **Ngôn ngữ:** [English](README.md) · [Tiếng Việt](README.vi.md)

## Người dùng cuối chỉ cần một URL

```
https://YOUR_DOMAIN/tv.m3u
```

Dán URL trên vào VLC / TiviMate / IPTV Smarters / OTT Navigator / Kodi — xong.
Không cần key, không cần token, không cần cấu hình gì thêm.
(`/xem.m3u` là alias tương đương.)

## Hoặc xem thẳng trên trình duyệt: `/xem`

`https://YOUR_DOMAIN/xem` là web player tích hợp sẵn (hls.js, giao diện tối,
lưới kênh có tìm kiếm + lọc nhóm + chọn chất lượng). Player phát đúng các
manifest `/hls/` đã tokenized như `/tv.m3u` — kể cả link token cá nhân dạng
`…/index.m3u8?token=…` mà bạn thêm vào `playlists/tv.m3u`.

Sidebar còn có **ô dán link**: dán bất kỳ URL `.m3u8` nào (kèm query string
`?token=…`) vào là CHRTV mint manifest proxy mã hoá có thời hạn cho link đó —
tiện để **thử link token mới trước khi thêm vào playlist**. URL dán vào phải
đi qua đúng các chặn SSRF/port như mọi fetch khác, không bao giờ hiện trong
response, và lúc phát vẫn có đầy đủ rewrite manifest, fallback, circuit-breaker.

- `POST /api/play {url}` → `{src: "/hls/{token}.m3u8", expires_at}` (6 giờ)
- `GET /api/channels` → JSON lưới kênh cho player (cùng identity binding với
  `/tv.m3u`; hỗ trợ `?key=…&mac=…` khi playlist bị khóa)
- Tắt tính năng dán-link bằng `ALLOW_URL_PLAY=false`; mặc định cũng tắt khi
  `PUBLIC_PLAYLIST=false` (bật lại tường minh bằng `ALLOW_URL_PLAY=true`).

Link token có thời hạn. Khi link chết: sửa `playlists/tv.m3u` với URL mới,
chờ sync kế tiếp (≤15 phút) hoặc bấm *Sync playlist* trong `/admin` — kênh
(và `/xem`) tự động nhảy sang link mới.

## Kiến trúc

```
GitHub M3U (playlists/tv.m3u)
      │  Cron 15 phút / Admin trigger
      ▼
 sync: fetch → hash check → parse → validate → normalize
      ▼
 Cloudflare D1 (channels, categories, users, sessions, keys, devices, auth logs)
      ▼
 /tv.m3u   POST /api/login → /p/{session}.m3u   /lg/{u}?{p}.m3u   Xtream API
      ▼
 /epg/{token}.xml   ── EPG token riêng, bind cùng identity
 /hls/{token}.m3u8  ── rewrite manifest, re-tokenize mọi URI
 /seg/{token}.ts    ── segment/key/subtitle passthrough (Range/206, không buffer)
      ▼
 upstream chết? → HLS error manifest hợp lệ (không bao giờ trả HTML cho player)
```

- **Token**: AES-256-GCM, chứa upstream URL + iat/exp và identity đã xác thực (`MAC`, `user_id`, `access_key_id`, `session_id` khi có), tamper-proof, tự hết hạn. Token con trong manifest kế thừa cùng identity; khi bật claim `ip`, token lấy từ IP khác bị chặn `403 TOKEN_BINDING_MISMATCH`. Mỗi lần tải manifest/EPG còn kiểm tra lại trạng thái user/key/session để revoke có hiệu lực trước khi chạm upstream. Upstream URL không xuất hiện trong playlist.
- **Rolling list theo người xem**: link playlist `/p/{session}.m3u` vẫn cố định, còn toàn bộ URL kênh bên trong gắn với một lease riêng được nhận diện bằng user/session/MAC/access-key cùng IP và User-Agent đã HMAC (không lưu username/IP thô trong bảng lease). Trong lúc player còn refresh manifest, tải lại list vẫn nhận đúng URL cũ để không mất buffer. Sau **60 giây không còn request manifest**, generation cũ hết hiệu lực; lần tải list kế tiếp tự sinh URL kênh mới và URL cũ trả `410 TOKEN_EXPIRED`. IP chỉ dùng tách viewer lease, không khóa cứng playback khi `TOKEN_BINDING` không chứa `ip`, nên đổi IP/CGNAT không cắt stream đang chạy.
- **SSRF guard**: chỉ http/https public; chặn localhost, private IP, link-local, metadata endpoints — kiểm tra cả từng hop redirect.
- **Circuit breaker**: upstream fail → failure state TTL 30s trong Cloudflare Cache; trong TTL trả ngay fallback manifest, hết TTL tự retry.
- **Proxy lồng (PHP/portal → m3u8 khác)**: nhiều nguồn trả một M3U 1 dòng trỏ sang playlist thật, hoặc chỉ echo URL. CHRTV tự follow (tối đa 2 hop), rồi mới rewrite — player không bao giờ nhận wrapper để đem đi demux như MPEG-TS.
- **Phân loại URI theo ngữ cảnh HLS, không đoán bằng đuôi file**: URI sau `#EXT-X-STREAM-INF` là manifest con; URI sau `#EXTINF` là media. Vì vậy relay kiểu PlayNow dùng cùng endpoint `index.m3u8?u=…` cho cả playlist lẫn segment vẫn được proxy đúng qua `/seg/`, không còn đem bytes MPEG-TS vào `/hls/` rồi load mãi.
- **DASH/MPD + ClearKey**: `#KODIPROP:inputstream.adaptive.manifest_type=mpd` (và `license_key=kid:key`) được parse lúc sync. Playlist/`/xem` phát `/mpd/{token}.mpd`; Kodi/TiviMate nhận lại KODIPROP; web player dùng dash.js. Referer/UA/`X-Access-Token` từ `#EXTVLCOPT`/`#KODIPROP` được gắn lúc fetch, không lộ ra client.
- **Fallback là playlist LIVE tạm, không phải "kênh chết"**: khi upstream hiccup, CHRTV trả playlist live rỗng (không `#EXT-X-ENDLIST`). VLC/TiviMate/hls.js sẽ tiếp tục hỏi lại và kênh TỰ phục hồi khi upstream sống lại — thay vì player kết luận "stream đã kết thúc" rồi văng ra, bắt bạn mở lại kênh sau mỗi lần giật 1 giây.
- **Channel health sweep**: cron `*/10 * * * *` chủ động probe batch kênh nhỏ (ưu tiên chưa check), đánh dấu `channel_health` online/offline/unknown → lộ ra qua `/api/admin/offline` + `health_status` ở `/api/admin/channels`. `offline` **chỉ khi link thật sự không vô được** (host không tới được, **im lặng quá 30s**, 404/410) và phải fail như vậy **2 lượt probe liên tiếp** mới chốt. Mọi trường hợp server vẫn trả lời — 5xx, 401/403/429/451 (auth/geo-block/rate-limit), 200 + body không phải HLS (trang anti-bot), port Worker không fetch được — đều là `unknown`, không bao giờ gán offline sai.
  Link cá nhân có credential trong query (`?token=…`, `?sign=…`, portal/MAC) **không bị probe**: sweep từ colo Cloudflare ngẫu nhiên trông y hệt chia sẻ tài khoản với hệ anti-abuse của relay/portal và có thể khiến link bị throttle/ban. Các kênh này giữ `unknown` với mã `PERSONAL_LINK` (bật lại bằng `HEALTH_PROBE_CREDENTIAL_LINKS=true`).
- **Playlist sync an toàn**: playlist mới lỗi → giữ nguyên version cũ, đánh dấu sync failed. Hash không đổi → không ghi lại DB. URL dùng cổng Cloudflare Worker không fetch được bị bỏ qua ngay lúc sync, nên `/tv.m3u` không phát link chắc chắn chỉ trả fallback/load mãi.
- **Session login an toàn**: `POST /api/login` đổi username/password thành URL
  `/p/{opaque-token}.m3u` không chứa password. Server chỉ lưu HMAC của token;
  session sống tới `users.expires_at` hoặc khi user/session bị revoke, đồng thời
  tuân thủ `max_connections` và hỗ trợ thay session cũ nhất.
- **Audit xác thực**: login, tải M3U và dùng access key/Xtream được ghi bền vững
  vào `auth_events`, gồm user/session, outcome, user-agent và **IP thô do
  Cloudflare quan sát** theo yêu cầu vận hành; tự dọn sau 30 ngày.
- **Honeypot + ban scanner**: các target scan lỗ hổng rõ ràng như `/.env`, `/.git/*`,
  `/wp-login.php`, `/phpmyadmin/*` trả 404 giả và ban IP edge quan sát được trong
  24 giờ. Bảng ban/counter chỉ giữ HMAC-SHA256 của IP. Request mà browser khai
  rõ `Sec-Fetch-Site: cross-site` vẫn nhận 404 giả nhưng không tạo ban, nên link
  hoặc embed độc hại từ site khác không thể ban nạn nhân. Scanner trực tiếp
  (không có Fetch Metadata) vẫn bị ban. Các path IPTV thường bị app probe
  (`/portal.php`, Stalker, Xtream) không nằm trong trap.
- **Private login chống brute-force**: `/lg/{username}?{password}.m3u` luôn xác
  thực user D1 dù playlist public đang bật. Năm lần sai trong 10 phút từ cùng IP
  tạo ban 24 giờ; counter bền vững qua các Cloudflare colo.

## Routes

| Route | Mô tả |
|---|---|
| `GET /` | Landing page (dark, minimal; không quảng bá URL playlist public) |
| `GET /xem` | Web player tích hợp: lưới kênh + dán-link `.m3u8?token=…` để xem ngay |
| `GET /ui/player.js` | Script web player (same-origin, không nhúng secret) |
| `GET /api/channels` | JSON lưới kênh cho player (binding như `/tv.m3u`) |
| `POST /api/play` | Mint manifest proxy 6 giờ cho một URL m3u8 dán vào (`ALLOW_URL_PLAY`) |
| `GET /login` | Portal user: đăng nhập, copy M3U, xem/revoke session/device |
| `GET /admin` | Dashboard bảo mật: users, sessions, audit, bans, keys/devices, health/sync |
| `GET /tv.m3u`, `/xem.m3u` | Playlist public chính (tuỳ chọn `?key=chr_…&mac=AA:BB:…`; token tự bind MAC/key/user) |
| `POST /api/login` | Đổi credential D1 thành opaque session và URL `/p/{token}.m3u` |
| `GET /api/account/sessions` | Liệt kê session của user hiện tại (Bearer session token) |
| `DELETE /api/account/sessions/{id}` | Revoke một session thuộc user hiện tại |
| `GET /p/{session}.m3u` | Playlist session không chứa username/password |
| `GET /lg/{username}?{password}.m3u` | Playlist riêng legacy; bắt buộc user/password D1, token bind user |
| `GET /epg/{token}.xml` | XMLTV qua token EPG riêng, có expiry/identity binding |
| `GET /hls/{token}.m3u8` | HLS manifest proxy (rewrite + re-tokenize mọi URI con; nếu body là MPD thì tự sniff sang DASH) |
| `GET /mpd/{token}.mpd` | DASH/MPD manifest proxy (rewrite BaseURL + SegmentTemplate) |
| `GET /seg/{token}[.ext]` | Media passthrough (ts/m4s/aac/mp4/key/vtt/subtitle) |
| `GET /dseg/{token}/{path}` | DASH segment theo prefix (player tự điền `$Number$` / `$Time$`) |
| `GET /player_api.php` | Xtream Codes API; luôn bắt buộc user D1 thật |
| `GET /get.php` | Xtream M3U; luôn bắt buộc user D1 thật |
| `GET /live/{user}/{pass}/{id}.m3u8` | Đổi Xtream credential thành redirect tới URL live opaque |
| `GET /xmltv.php`, `/epg.xml` | Đổi Xtream credential thành redirect tới EPG tokenized |
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
GET    /api/admin/security-bans     # ban còn hiệu lực; chỉ có HMAC IP, không có IP thô
DELETE /api/admin/security-bans/{ipHash} # gỡ ban (propagate cache toàn cầu trong ≤60s)
GET    /api/admin/auth-events[?limit=N]  # login/M3U/Xtream/access-key audit, có IP thô
GET    /api/admin/sessions          # session/device user, IP đầu/cuối, trạng thái
DELETE /api/admin/sessions/{id}     # revoke session bất kỳ
GET    /api/admin/offline           # kênh đang bị đánh dấu offline (health sweep)
POST   /api/admin/health-check[?limit=N] # chủ động probe một batch kênh ngay
GET    /api/admin/users             # không bao giờ trả password hash
POST   /api/admin/users             # {username, password, expires_at?, max_connections?}
PATCH  /api/admin/users/{id}        # {status?, expires_at?, max_connections: 1..100}
DELETE /api/admin/users/{id}        # đánh dấu user revoked và revoke session đang active
GET    /api/admin/keys
POST   /api/admin/keys              # {label?, max_devices?, user_id?}; trả raw key đúng MỘT lần
PATCH  /api/admin/keys/{id}         # {status?} và/hoặc {user_id: number|null}
DELETE /api/admin/keys/{id}
GET    /api/admin/devices
GET    /api/admin/devices/mac/{mac}
PATCH  /api/admin/devices/{id}
DELETE /api/admin/devices/{id}
```

Dashboard tại `https://YOUR_DOMAIN/admin` gọi các API trên cùng origin. Nhập
`ADMIN_TOKEN` trong browser; token được giữ trong `sessionStorage`, không được
nhúng vào HTML/source. Dashboard hỗ trợ user/expiry/connection limit, session
revoke, ban/unban, audit login với raw IP, access key/device, health check và
playlist sync. Vì audit chứa dữ liệu cá nhân (IP thô), chỉ cấp `ADMIN_TOKEN` cho
người vận hành và giữ retention mặc định 30 ngày.

### Đăng nhập an toàn và quản lý session/device

Mở `https://YOUR_DOMAIN/login`, hoặc gọi API trực tiếp:

```bash
curl -X POST https://YOUR_DOMAIN/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ken","password":"use-a-strong-password","device_name":"TV phòng khách"}'
```

Kết quả `201` trả `access_token`, `playlist_url` dạng
`https://YOUR_DOMAIN/p/{opaque-token}.m3u` và metadata session. URL M3U không chứa
username/password; D1 chỉ lưu `HMAC-SHA256(token)` và prefix không bí mật, không
lưu raw token. Response login/account/playlist luôn `private, no-store` và
`Referrer-Policy: no-referrer`.

- Session không có TTL 30 ngày riêng: hạn của nó là `users.expires_at` (hoặc vô
  hạn nếu account chưa đặt hạn). Playlist dùng mốc sớm hơn giữa hạn session đang
  lưu và hạn account hiện tại; media/EPG cùng mọi token HLS con không bao giờ
  vượt mốc đó. Mỗi lần tải manifest/EPG kiểm tra lại D1 nên session/user bị revoke,
  disabled, expired hoặc deleted sẽ dừng trước khi Worker gọi upstream.
- `max_connections` (1–100) giới hạn số session active. Nếu đã đầy, API trả
  `409 SESSION_LIMIT`; gửi `"replace_oldest": true` để revoke session dùng lâu
  nhất rồi tạo session mới.
- `GET /api/account/sessions` với `Authorization: Bearer {access_token}` liệt kê
  thiết bị/session của đúng user đó; `DELETE /api/account/sessions/{id}` chỉ
  revoke được session cùng owner. Admin có thể xem/revoke toàn bộ tại `/admin`.
- Portal giữ bearer token trong `sessionStorage` của browser, không nhúng secret
  vào HTML và không đưa password vào URL. Với IPTV player không hỗ trợ POST, đăng
  nhập một lần trên portal rồi copy `playlist_url`.

Ví dụ liệt kê session:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://YOUR_DOMAIN/api/account/sessions
```

### Playlist riêng legacy qua `/lg`

Tạo user D1 qua Admin API (password tối thiểu 8 ký tự), sau đó dùng URL dạng:

```text
https://YOUR_DOMAIN/lg/ken?use-a-strong-password.m3u
```

Phần ngay sau dấu `?` tới trước suffix `.m3u` là password, **không** phải query
`password=...`. Username/password có ký tự reserved phải percent-encode. Route
này không nhận guest: nó luôn gọi user D1 và kiểm tra trạng thái/hạn dùng, kể cả
khi `PUBLIC_PLAYLIST="true"`. M3U trả về chỉ chứa token opaque được bind với
`user_id` đã xác thực (và các claim khác theo `TOKEN_BINDING`). Response
là `private, no-store` và không referrer; CHRTV không ghi query/password vào log.

Sai credential trả cùng một `AUTH_INVALID` để không lộ username tồn tại. Counter
brute-force lưu theo HMAC của IP trong D1: **5 lần sai / 10 phút** sẽ ban IP một
ngày. Lần thứ 5 trả `429`, các request sau trả `403 SECURITY_BANNED` tới khi hết
hạn hoặc admin gọi `DELETE /api/admin/security-bans/{ipHash}`.

> Credential nằm trong URL theo format yêu cầu nên có thể xuất hiện trong access
> log của hạ tầng phía trước Worker. Luôn dùng HTTPS, password mạnh/riêng và hạn
> chế chia sẻ URL.

### Token theo MAC / user ID / access key

Mỗi lần trả M3U, CHRTV tạo identity binding từ địa chỉ edge quan sát được,
credential đã xác thực và device label do client khai. Các claim được bật bằng
`TOKEN_BINDING` (**mặc định `"mac,user,key"`**):

- `mac`: lấy từ `?mac=`, normalize về `AA:BB:CC:DD:EE:FF`, đồng thời đăng ký
  device nếu playlist dùng access key. MAC, IP và các ID đều nằm **bên trong
  payload AES-GCM**, không lộ plaintext trong URL.
- `user_id`: lấy từ user D1 đã đăng nhập qua Xtream, hoặc từ access key được
  link user bằng `user_id`. Client không thể tự khai `user_id` qua query.
- `access_key_id`: tự gắn khi dùng `?key=chr_…`, nên ngay cả hai key cùng
  IP/MAC vẫn nhận token khác nhau.
- `session_id`: luôn gắn cùng owner `user_id` vào playlist từ `/p/{session}.m3u`,
  kể cả khi operator đặt `TOKEN_BINDING=none`; đây là capability phục vụ revoke,
  không phải claim tùy chọn do client khai.
- `ip`: **tắt mặc định** (xem ghi chú bên dưới); khi bật, chỉ lấy từ header edge
  tin cậy `CF-Connecting-IP` (không tin `X-Forwarded-For`) và mọi request `/hls`
  và `/seg` phải đến từ đúng IP này; khác IP trả `403 TOKEN_BINDING_MISMATCH`
  trước khi chạm upstream.

> **Vì sao `ip` không còn là mặc định:** bind token theo IP lúc tải playlist làm
> hỏng phát sóng khi IP xem khác IP đăng nhập/lấy playlist — đăng nhập trên PC
> rồi mở trên TV box, hoặc ISP đổi IP công khai (CGNAT rất phổ biến ở VN). Hệ
> quả là `403 TOKEN_BINDING_MISMATCH` và "xem không được" dù credential đúng.
> Token vẫn bind vào user/session D1 (`uid`/`sid`) và access key, nên revoke
> user/session vẫn cắt stream ngay lập tức. Bật lại `ip` nếu muốn chống chia sẻ
> nghiêm ngặt nhất và luôn fetch + xem trên cùng một mạng.

Các token manifest/segment sinh tiếp theo kế thừa đủ binding trên. Playlist còn
đưa `url-tvg`/`x-tvg-url` về `/epg/{token}.xml`; token EPG có kind riêng nên
không thể lấy token manifest/segment thế vào. URI con trong HLS — child manifest,
segment, encryption key, init map và subtitle — đều phải rewrite thành token;
nếu một URI không an toàn hoặc không token hóa được, CHRTV fail closed và trả
fallback HLS an toàn thay vì lộ URL upstream. Fallback manifest còn ghi kèm mã
lỗi nội bộ (ví dụ `UNSUPPORTED_PORT`, `UPSTREAM_4XX`) trong dòng comment để dễ
biết kênh hỏng vì lý do gì.

Token vẫn ổn định trong cửa sổ 10 phút **cho cùng identity**, nhưng khác
MAC/user/key sẽ khác nhau. Request playlist bằng access key đã link cũng bị
từ chối khi user owner bị disable, revoked hoặc hết hạn. Access key link user có
thể tạo bằng:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"TV phòng khách","user_id":12,"max_devices":2}' \
  https://YOUR_DOMAIN/api/admin/keys
```

> MAC phần cứng là thông tin layer 2, server HTTP trên Internet không thể tự
> đọc nó. Vì vậy MAC ở đây là device identity do client khai báo, được ràng buộc
> với access key và dùng để cá nhân hoá token/giới hạn thiết bị; credential thật
> vẫn là access key.

### Phát hiện kênh offline (channel health)

Circuit breaker ở proxy chỉ ghi lỗi khi **viewer thực sự bật** vào một kênh chết
(`stream_failures`). Một kênh hỏng link mà chưa ai xem sẽ vẫn hiện "active" trong
playlist mãi. CHRTV bổ sung một **health sweep chủ động**:

- Cron `*/10 * * * *` probe một batch nhỏ (hard cap **12** kênh/lần, xem giải thích
  subrequest bên dưới) kênh active, ưu tiên kênh **chưa được check bao giờ / lâu
  nhất**, xoay vòng đều.
- Mỗi probe fetch upstream (cùng luật SSRF + port-safe như proxy), follow redirect
  và xác nhận body có phải HLS không.
- **Probe chờ tới 30s** (tổng ngân sách cho cả chuỗi redirect) trước khi kết luận
  timeout: relay chậm kiểu devda.undo.it bounce qua CDN mất 10-25s mới ra byte
  đầu — load lâu nhưng vẫn phát bình thường. Timeout ngắn (6-8s) gán offline oan
  cho mấy kênh này mỗi lần quét.
- **`offline` chỉ dành cho link thật sự KHÔNG VÔ ĐƯỢC**: host không tới được
  (DNS chết / connection refused), im lặng quá 30s, hoặc 404/410 (link không còn
  tồn tại). Server còn trả lời được — dù là 5xx (đang quá tải / restart),
  401/403/429/451 (auth / geo-block / rate-limit), hay 200 + body không phải HLS
  (thường là trang anti-bot chỉ hiện với probe datacenter, player thật vẫn xem
  được) — nghĩa là link **vẫn vô được**, đánh dấu `unknown` kèm `error_code`,
  **không** bao giờ tính là offline. Cron trigger chạy ở **colo ngẫu nhiên** của
  Cloudflare (có thể ngoài lãnh thổ VN), nên một kênh geo-block nước ngoài vẫn
  hoàn toàn xem được với viewer trong nước — gán offline cho nó là sai.
- **Phải fail 2 lượt probe liên tiếp mới chốt offline** (`fail_streak` trong
  `channel_health`): một lần fail có thể chỉ là một nhịp mạng xấu ở colo chạy
  cron. Lần fail đầu ghi `unknown` (vẫn giữ `error_code` để admin thấy kênh đáng
  ngờ); lần thứ hai liên tiếp mới flip sang `offline`. Probe thành công hoặc
  không kết luận được → reset streak về 0, nên kênh chập chờn không bao giờ bị
  báo offline oan.
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

# 2. Chạy migrations (bao gồm 0005–0009: token identity, bans, sessions/audit, play_opts, viewer lease)
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
- `EPG_URL` — nguồn XMLTV upstream (tuỳ chọn); URL này không lộ cho client,
  playlist chỉ nhận `/epg/{token}.xml`
- `PUBLIC_PLAYLIST` — `"true"` (mặc định): chỉ `/tv.m3u`/`xem.m3u` mở tự do;
  `"false"`: bắt buộc `?key=`. Biến này **không** cho phép Xtream hoặc login
  dùng credential tuỳ ý; các endpoint đó luôn xác thực user thật trong D1
- `TOKEN_BINDING` — danh sách claim phân cách bằng dấu phẩy: `ip`, `mac`, `user`, `key`.
  Mặc định `"mac,user,key"`; có thể chọn riêng, ví dụ `"ip,user"` hoặc
  `"mac,user,key"`. `"none"` tắt identity binding có chủ đích. Giá trị sai tự
  fail-safe về mặc định đầy đủ, không âm thầm tắt bảo vệ.
- `HONEYPOT_ENABLED` — mặc định `"true"`; đặt `"false"` chỉ để tắt nhận diện
  scanner trap. Ban đã tồn tại và brute-force protection vẫn tiếp tục áp dụng.
- `HONEYPOT_BAN_SECONDS` — thời gian ban honeypot/brute-force, mặc định `86400`
  (một ngày), tối thiểu 60 giây và clamp tối đa 7 ngày.
- `FALLBACK_M3U_URL` — (tuỳ chọn) playlist HLS phát thay khi kênh chết. Cho phép **nhiều URL,
  ngăn cách bằng dấu phẩy**, thử lần lượt:
  1. URL nằm trên port Worker fetch được → CHRTV fetch + re-proxy (segment thành `/seg/{token}`),
     không lộ URL fallback, chạy được cả trên trang https.
  2. URL nằm trên port Worker **không** fetch được (ví dụ `:30113`) → bỏ qua, tuyệt đối không
     redirect client tới origin thô.
  3. Không có URL proxy được → manifest "signal lost" rỗng mặc định.
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

CHRTV kiểm tra trước khi fetch và áp dụng **strict origin hiding**:

- URL kênh trong playlist dùng port không hợp lệ → bị bỏ qua ngay lúc sync và
  không xuất hiện trong `/tv.m3u`. Với capability cũ hoặc channel được ghi trực
  tiếp vào D1, Worker vẫn từ chối fetch, thử fallback proxy được và không bao giờ
  chứa origin thô hay `Location` trỏ tới origin đó trong response.
- URI con trong manifest dùng port không hợp lệ → từ chối cả manifest trước khi
  phát capability con, rồi failover/fail closed; không tạo URL con không dùng được.
- `FALLBACK_M3U_URL` dùng port không hợp lệ (ví dụ `:30113`) → bỏ qua candidate,
  không redirect player và không lộ URL trong response.

Nguồn custom-port muốn tiếp tục phát phải được đặt sau **HTTPS port 443**, đưa qua
**Cloudflare Tunnel**, hoặc qua một **relay riêng** trên port Worker fetch được.
CHRTV không dùng User-Agent/camouflage để chỉ che origin với scanner: cùng một luật
không-disclosure áp dụng cho curl, player và trình duyệt.

### Chống "connection is unstable"

- **Token ổn định theo identity**: cùng một segment/kênh + MAC/user/key luôn
  ra cùng URL trong cửa sổ 10 phút (IV suy ra bằng HMAC trên cả seed + payload
  thay vì random); identity khác nhận URL khác → player tái sử dụng buffer, không tải lại
  toàn bộ segment mỗi lần refresh manifest.
- **Timeout 30s cho cả manifest lẫn segment**: relay chậm (devda.undo.it → CDN)
  load 10-25s vẫn vào kênh bình thường — chỉ khi upstream **im lặng quá 30s** mới
  tính chết, mở circuit breaker và bật fallback.
- **30s là TỔNG ngân sách chờ, không phải mỗi hop**: deadline chia sẻ cho toàn bộ
  chuỗi redirect + cả lần retry. Trước đây mỗi hop redirect được cấp lại 30s mới,
  chuỗi 6 hop chậm có thể bắt player nhìn spinner tới ~3 phút ("load video quá
  lâu") mới thấy fallback — giờ tệ nhất cũng chỉ ~30s đúng như policy.
- **Cache segment 30s trên edge Cloudflare**: segment live là bất biến sau khi
  publish, và token segment là deterministic nên cùng một segment luôn ra cùng
  một URL. Chỉ request ĐẦU TIÊN phải chịu TTFB 10-25s của relay chậm; player
  retry / viewer thứ hai / nhánh ABR lấy lại segment đó nhận ngay từ cache —
  giảm hẳn cảnh "load video quá lâu" khi nhiều người cùng xem. Chỉ body 2xx
  mới được cache (status-aware), nên một 4xx/5xx thoáng qua không bị phát lại
  cho mọi viewer suốt TTL. Range request đi thẳng upstream.
- **Retry 1 lần** cho lỗi tạm thời fail nhanh (mạng / 5xx) trước khi mở circuit
  breaker — nhưng chỉ với phần thời gian còn lại của ngân sách 30s. Timeout đã
  là kết luận đủ chắc nên **không retry** (tránh kéo dài 60s trước khi player
  nhận được fallback).
- **`FORWARD_CLIENT_IP=true` cho relay tự host**: relay kiểu MAC-portal/playnow
  authorize/geo-fence/rate-limit theo client IP; nếu không bật, chúng chỉ thấy IP
  datacenter Cloudflare (đổi theo colo) — VLC mở trực tiếp từ nhà thì được, còn
  đúng link đó đi qua proxy lại ăn 403 / trang "Upstream HTTP 403". Khi bật, IP
  thật của viewer được gắn vào `X-Forwarded-For`/`X-Real-IP` để relay áp rule lên
  đúng người xem. Nếu server của *seller* chặn hẳn IP datacenter (kiểm tra
  `/admin` → failures: `UPSTREAM_UNREACHABLE`/`UPSTREAM_TIMEOUT` trong khi VLC ở
  nhà vẫn xem ngon), code worker không vượt được — hãy cho relay của bạn proxy
  bytes thay vì 302-redirect về origin IP:port.
- **SEGMENT_TTL 60 phút** (trước là 15) → token không hết hạn giữa chừng khi đang xem.
- **Không forward `accept-encoding`**, ép `identity` → body không bị giải nén lệch
  `Content-Length` làm player thấy segment cụt.

### Xtream Codes

Xtream **luôn yêu cầu user thật đang active trong D1**, bất kể
`PUBLIC_PLAYLIST`. Credential sai/thiếu không được biến thành guest access;
`/tv.m3u` là route duy nhất được phép public theo cấu hình. Login success,
failure và blocked được ghi `auth_events` với raw client IP và áp dụng cùng
brute-force ban như các flow username/password khác.

CHRTV đọc thông tin đăng nhập từ **mọi cách client gửi**: query string,
form POST, **JSON POST** (IPTV Smarters) và **HTTP Basic auth**.

Endpoint được hỗ trợ:

| Route | Dùng bởi |
|---|---|
| `/player_api.php`, `/player-api.php`, `/playerapi.php` | TiviMate, Smarters, OTT Navigator |
| `/panel_api.php` | client cũ (trả nguyên `available_channels` + `categories`) |
| `/get.php`, `/enigma2.php` | tải M3U |
| `/live/{u}/{p}/{id}`, `/{u}/{p}/{id}` | phát kênh (dạng có và không có tiền tố `/live`) |
| `/xmltv.php`, `/epg.xml` | EPG Xtream có credential |

`get.php` và live records trong player API chỉ xuất URL media opaque. Route live
có credential xác thực rồi redirect sang `/hls/{token}.m3u8`; XMLTV có credential
redirect sang `/epg/{token}.xml`. Vì vậy password không truyền tiếp vào URI con,
và upstream media/EPG không lộ qua response API.

Cấu hình trong player:

```
Server / Portal URL : https://YOUR_DOMAIN     (không thêm /get.php, không thêm port)
Username            : user đã tạo trong D1
Password            : password đúng của user
```

## Development & test

```bash
npm run dev        # wrangler dev (cần .dev.vars, xem .dev.vars.example)
npm test           # unit + integration, chạy trong workerd
npm run typecheck
npm run build      # wrangler deploy --dry-run
```

## Playlist

Sửa `playlists/tv.m3u`, commit lên `main` — cron sẽ tự sync trong ≤15 phút,
hoặc `POST /api/admin/sync` để sync ngay.

## License

MIT
