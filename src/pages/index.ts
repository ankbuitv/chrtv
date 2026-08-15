/** Minimal dark landing + "Signal Lost" 404, rendered inline — no framework. */

const BASE_STYLE = `
:root{color-scheme:dark}
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:radial-gradient(1200px 800px at 70% -10%,#12203a 0%,#0a0f1a 55%,#070b12 100%);
  color:#e6edf6;font-family:ui-sans-serif,system-ui,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
.card{backdrop-filter:blur(14px);background:rgba(255,255,255,.045);
  border:1px solid rgba(255,255,255,.09);border-radius:20px;
  padding:56px 64px;text-align:center;box-shadow:0 24px 80px rgba(0,0,0,.5);max-width:520px;margin:24px}
.logo{font-size:44px;font-weight:800;letter-spacing:.18em;
  background:linear-gradient(92deg,#7dd3fc 0%,#818cf8 55%,#c084fc 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.tag{margin-top:10px;font-size:14px;letter-spacing:.32em;text-transform:uppercase;color:#8b98ad}
.meta{margin-top:34px;display:flex;gap:14px;justify-content:center;flex-wrap:wrap}
.pill{font-size:12px;padding:7px 15px;border-radius:999px;border:1px solid rgba(255,255,255,.1);
  background:rgba(255,255,255,.04);color:#aeb9cc;letter-spacing:.06em}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:7px;vertical-align:1px}
.ok{background:#34d399;box-shadow:0 0 8px #34d39988}
.warn{background:#f59e0b;box-shadow:0 0 8px #f59e0b88}
.foot{margin-top:36px;font-size:12px;color:#5b6778}
code{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);
  border-radius:8px;padding:3px 9px;font-size:13px;color:#9fd3ff}
`;

export function landingPage(status: { syncStatus: string; channelCount: string; lastSync: string }): Response {
  const ok = status.syncStatus === 'ok';
  const dotClass = ok ? 'ok' : 'warn';
  const syncLabel = ok ? 'Playlist synced' : status.syncStatus === 'never' ? 'Awaiting first sync' : 'Sync degraded';
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CHRTV — Cloud IPTV Gateway</title><style>${BASE_STYLE}</style></head>
<body><main class="card">
  <div class="logo">CHRTV</div>
  <div class="tag">Cloud IPTV Gateway</div>
  <div class="meta">
    <span class="pill"><span class="dot ok"></span>Online</span>
    <span class="pill"><span class="dot ${dotClass}"></span>${syncLabel}</span>
    <span class="pill">${status.channelCount || '0'} channels</span>
  </div>
  <div class="foot">Playlist endpoint: <code>/tv.m3u</code></div>
</main></body></html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

export function notFoundPage(requestId: string): Response {
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>404 — Signal Lost · CHRTV</title><style>${BASE_STYLE}
.err{font-size:80px;font-weight:800;letter-spacing:.06em;color:#e6edf6;
  text-shadow:0 0 40px rgba(129,140,248,.35)}
.lost{margin-top:6px;font-size:15px;letter-spacing:.5em;text-transform:uppercase;color:#7d8aa0}
.bars{display:flex;gap:5px;justify-content:center;margin-top:30px;height:26px;align-items:flex-end}
.bars span{width:6px;background:linear-gradient(180deg,#818cf8,#312e81);border-radius:2px;
  animation:flk 1.2s infinite ease-in-out}
.bars span:nth-child(1){height:40%;animation-delay:0s}
.bars span:nth-child(2){height:90%;animation-delay:.15s}
.bars span:nth-child(3){height:60%;animation-delay:.3s}
.bars span:nth-child(4){height:100%;animation-delay:.45s}
.bars span:nth-child(5){height:50%;animation-delay:.6s}
@keyframes flk{0%,100%{opacity:.25}50%{opacity:1}}
</style></head>
<body><main class="card">
  <div class="logo" style="font-size:22px">CHRTV</div>
  <div class="err">404</div>
  <div class="lost">Signal Lost</div>
  <div class="bars"><span></span><span></span><span></span><span></span><span></span></div>
  <div class="foot">The channel you tuned to does not exist.</div>
</main></body></html>`;
  return new Response(html, {
    status: 404,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Request-ID': requestId },
  });
}
