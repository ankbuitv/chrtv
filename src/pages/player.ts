/**
 * /xem — the built-in web player.
 *
 * Watches any channel synced from the playlist (including token links like
 * …/index.m3u8?token=…) directly in the browser: the page lists the same
 * tokenized /hls/ manifests /tv.m3u serves, and plays them via hls.js (or
 * native HLS on Safari/iOS). A paste box lets the operator try a brand-new
 * token link through the proxy before adding it to the playlist.
 *
 * No secrets are embedded in the HTML; tokens are fetched per session from
 * /api/channels and /api/play. The page works without JavaScript from jsDelivr
 * only in native-HLS browsers; elsewhere hls.js is loaded from the CDN with a
 * graceful error hint when it is unavailable.
 */

const PLAYER_STYLE = `
:root{color-scheme:dark;--bg:#070b12;--panel:#101827;--line:#263247;--text:#e6edf6;--muted:#8b98ad;--accent:#7dd3fc;--good:#34d399;--bad:#fb7185}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:radial-gradient(1000px 700px at 80% -10%,#152744,var(--bg) 60%);color:var(--text);font-family:ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;display:flex;flex-direction:column}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 18px;border-bottom:1px solid var(--line);background:rgba(7,11,18,.85);position:sticky;top:0;z-index:5;backdrop-filter:blur(10px)}
.brand{font-size:20px;font-weight:850;letter-spacing:.12em;color:var(--accent);text-decoration:none}
.hint{color:var(--muted);font-size:12.5px}
.wrap{display:flex;flex:1;min-height:0}
aside{width:320px;min-width:260px;border-right:1px solid var(--line);display:flex;flex-direction:column;padding:12px;gap:10px}
.paste{display:flex;gap:8px}
.paste input{flex:1;min-width:0;font:inherit;font-size:13px;border-radius:9px;border:1px solid var(--line);padding:9px 10px;background:#0a111e;color:var(--text)}
button{font:inherit;border-radius:9px;border:1px solid var(--line);padding:9px 12px;background:#18283f;color:var(--text);cursor:pointer}
button:hover{border-color:#5681ac}
button.primary{background:#155e75;border-color:#0e7490}
.filters{display:flex;gap:8px}
.filters input,.filters select{flex:1;min-width:0;font:inherit;font-size:13px;border-radius:9px;border:1px solid var(--line);padding:9px 10px;background:#0a111e;color:var(--text)}
#list{flex:1;overflow:auto;display:flex;flex-direction:column;gap:6px;padding-right:2px}
.ch{display:flex;align-items:center;gap:10px;text-align:left;border:1px solid transparent;background:rgba(16,24,39,.6);border-radius:10px;padding:8px 10px;font-size:13.5px;line-height:1.25}
.ch:hover{border-color:var(--line)}
.ch.active{border-color:var(--accent);background:rgba(21,94,117,.25)}
.ch img{width:38px;height:38px;border-radius:8px;object-fit:contain;background:#0a111e;flex:none}
.ch .noimg{width:38px;height:38px;border-radius:8px;background:#0a111e;flex:none;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:15px}
.ch .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ch .gp{display:block;color:var(--muted);font-size:11px}
main{flex:1;display:flex;flex-direction:column;min-width:0}
.stage{position:relative;background:#000;flex:1;min-height:280px;display:flex;align-items:center;justify-content:center}
video{width:100%;height:100%;max-height:calc(100vh - 170px);background:#000}
.msg{position:absolute;inset:auto 0 0 0;padding:10px 14px;font-size:13px;background:rgba(7,11,18,.82);color:var(--muted);text-align:center;pointer-events:none}
.bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 14px;border-top:1px solid var(--line)}
.bar .title{flex:1;min-width:160px;font-weight:650;font-size:14.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#quality{font-size:13px;padding:7px 9px}
.state{font-size:12.5px}
.state.ok{color:var(--good)}.state.err{color:var(--bad)}
footer{padding:8px 18px;border-top:1px solid var(--line);color:#5b6778;font-size:12px;display:flex;gap:14px;flex-wrap:wrap}
footer a{color:#7d97b8}
@media(max-width:760px){.wrap{flex-direction:column}aside{width:100%;max-height:44vh;border-right:none;border-bottom:1px solid var(--line)}video{max-height:56vh}}
`;

export function playerPage(): Response {
  const html = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CHRTV — Xem TV</title>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js" defer></script>
<style>${PLAYER_STYLE}</style></head>
<body>
<header><a class="brand" href="/">CHRTV · XEM</a><span class="hint" id="count">Đang tải danh sách kênh…</span></header>
<div class="wrap">
<aside>
  <form class="paste" id="paste-form"><input id="paste-url" type="text" placeholder="Dán link .m3u8 (có ?token=…) để thử" autocomplete="off" spellcheck="false"><button class="primary" type="submit">Xem</button></form>
  <div class="filters"><input id="search" type="search" placeholder="Tìm kênh…" autocomplete="off"><select id="group"><option value="">Tất cả nhóm</option></select></div>
  <div id="list"></div>
</aside>
<main>
  <div class="stage"><video id="video" controls playsinline></video><div class="msg" id="msg"></div></div>
  <div class="bar"><span class="title" id="title">Chưa chọn kênh</span><select id="quality"><option value="-1">Tự động</option></select><button id="retry">Tải lại</button><button id="copy-src">Copy link .m3u8</button><button id="fs">Toàn màn hình</button><span class="state" id="state"></span></div>
</main>
</div>
<footer><span>Mở trong app: <a href="/tv.m3u">/tv.m3u</a></span><span>Link token hết hạn? Sửa <code>playlists/tv.m3u</code> rồi chờ sync (~15 phút) hoặc bấm Sync trong /admin.</span></footer>
<script src="/ui/player.js" defer></script></body></html>`;
  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy':
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; img-src 'self' data: https:; media-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  });
}

const PLAYER_JS = String.raw`
const $=s=>document.querySelector(s);
const video=$('#video'),listEl=$('#list'),msgEl=$('#msg'),stateEl=$('#state'),titleEl=$('#title'),qualityEl=$('#quality'),groupEl=$('#group'),searchEl=$('#search'),countEl=$('#count');
let channels=[],hls=null,current=null,retries=0;

// Access key (non-public deployments): remember ?key=&mac= for API calls.
const qs=new URLSearchParams(location.search);
const auth=()=>{const p=new URLSearchParams();const key=sessionStorage.getItem('chrtv_key')||qs.get('key');const mac=sessionStorage.getItem('chrtv_mac')||qs.get('mac');if(key){p.set('key',key);if(mac)p.set('mac',mac)}return p.toString()};
if(qs.get('key'))sessionStorage.setItem('chrtv_key',qs.get('key'));
if(qs.get('mac'))sessionStorage.setItem('chrtv_mac',qs.get('mac'));

const setState=(t,cls='')=>{stateEl.textContent=t;stateEl.className='state '+cls};
const setMsg=t=>{msgEl.textContent=t||''};

function destroy(){if(hls){hls.destroy();hls=null}video.removeAttribute('src');video.load()}

function play(src,title){
  current={src,title};titleEl.textContent=title;retries=0;destroy();setMsg('Đang kết nối…');setState('');
  qualityEl.innerHTML='<option value="-1">Tự động</option>';
  const native=video.canPlayType('application/vnd.apple.mpegurl');
  if(window.Hls&&Hls.isSupported()){
    hls=new Hls({enableWorker:true,liveSyncDurationCount:3,fragLoadingMaxRetry:4,manifestLoadingMaxRetry:2});
    hls.on(Hls.Events.MANIFEST_PARSED,()=>{setMsg('');setState('Đang phát ●','ok');video.play().catch(()=>{})});
    hls.on(Hls.Events.LEVEL_SWITCHED,(e,d)=>{const auto=qualityEl.value==='-1';const idx=auto?d.level:Number(qualityEl.value);const l=hls.levels[idx];if(l)setState((auto?'Tự động · ':'')+(l.height?l.height+'p':Math.round((l.bitrate||0)/1000)+'kbps'),'ok')});
    hls.on(Hls.Events.ERROR,(e,d)=>{
      if(!d.fatal){return}
      if(d.type===Hls.ErrorTypes.NETWORK_ERROR&&retries<3){retries++;setMsg('Mất kết nối, thử lại lần '+retries+'…');setTimeout(()=>hls&&hls.startLoad(),1500);return}
      if(d.type===Hls.ErrorTypes.MEDIA_ERROR&&retries<3){retries++;setMsg('Lỗi giải mã, khôi phục…');hls.recoverMediaError();return}
      setMsg('');setState('Không phát được — kênh có thể offline hoặc link token hết hạn','err');
    });
    hls.loadSource(src);hls.attachMedia(video);
    hls.on(Hls.Events.MANIFEST_PARSED,()=>{
      if(!hls||!hls.levels||hls.levels.length<2)return;
      qualityEl.innerHTML='<option value="-1">Tự động</option>'+hls.levels.map((l,i)=>'<option value="'+i+'">'+(l.height?l.height+'p':Math.round((l.bitrate||0)/1000)+'kbps')+'</option>').join('');
    });
  }else if(native){
    video.src=src;video.play().catch(()=>{});
    setMsg('');setState('Đang phát ● (HLS gốc)','ok');
  }else{
    setMsg('');setState('Trình duyệt không hỗ trợ HLS và không tải được hls.js (mạng/CDN chặn?)','err');
  }
}
qualityEl.onchange=()=>{if(hls)hls.currentLevel=Number(qualityEl.value)};
$('#retry').onclick=()=>{if(current)play(current.src,current.title)};
$('#fs').onclick=()=>{if(document.fullscreenElement)document.exitFullscreen();else$('.stage').requestFullscreen&&$('.stage').requestFullscreen()};
$('#copy-src').onclick=async()=>{if(!current)return;await navigator.clipboard.writeText(new URL(current.src,location.origin).toString());setState('Đã copy link .m3u8 (link app dùng trực tiếp được)','ok')};

function render(){
  const g=groupEl.value,q=searchEl.value.trim().toLowerCase();
  const items=channels.filter(c=>(!g||c.group===g)&&(!q||c.name.toLowerCase().includes(q)));
  listEl.textContent='';
  for(const c of items){
    const b=document.createElement('button');b.type='button';b.className='ch'+(current&&current.src===c.url?' active':'');
    if(c.logo){const img=document.createElement('img');img.src=c.logo;img.loading='lazy';img.alt='';img.onerror=()=>{img.replaceWith(noImg())};b.append(img)}else b.append(noImg());
    const nm=document.createElement('span');nm.className='nm';nm.textContent=c.name;const gp=document.createElement('span');gp.className='gp';gp.textContent=c.group;nm.prepend(gp);b.append(nm);
    b.onclick=()=>{play(c.url,c.name);history.replaceState(null,'','/xem?ch='+encodeURIComponent(c.id))};
    listEl.append(b);
  }
  countEl.textContent=items.length+' / '+channels.length+' kênh';
}
function noImg(){const d=document.createElement('span');d.className='noimg';d.textContent='📺';return d}
groupEl.onchange=render;searchEl.oninput=render;

async function load(){
  try{
    const a=auth();const res=await fetch('/api/channels'+(a?'?'+a:''),{headers:{'Accept':'application/json'}});
    const body=await res.json();
    if(!res.ok)throw new Error(body.error||('HTTP '+res.status));
    channels=body.channels||[];
    const groups=[...new Set(channels.map(c=>c.group))];
    groupEl.innerHTML='<option value="">Tất cả nhóm ('+groups.length+')</option>'+groups.map(g=>'<option>'+g.replace(/[&<>"]/g,'')+'</option>').join('');
    render();
    const ch=new URLSearchParams(location.search).get('ch');
    const pre=ch?channels.find(c=>c.id===ch):null;
    if(pre)play(pre.url,pre.name);
  }catch(e){countEl.textContent='Không tải được kênh';setState('Lỗi: '+e.message+' — cần ?key=… nếu playlist đang khóa','err')}
}

$('#paste-form').onsubmit=async e=>{
  e.preventDefault();
  const url=$('#paste-url').value.trim();
  if(!url)return;
  setState('Đang tạo link xem…');setMsg('');
  try{
    const res=await fetch('/api/play',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const body=await res.json();
    if(!res.ok)throw new Error(body.error||('HTTP '+res.status));
    play(body.src,'Link dán · '+new URL(url).hostname);
    $('#paste-url').value='';
  }catch(err){setState('Không xem được: '+err.message,'err')}
};

// ?url=<m3u8> — mở luôn player với một link token cụ thể.
const preUrl=qs.get('url');
load().then(()=>{if(preUrl)$('#paste-form').requestSubmit()});
`;

export function playerScript(): Response {
  return new Response(PLAYER_JS, {
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
