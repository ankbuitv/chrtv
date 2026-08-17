const PORTAL_STYLE = `
:root{color-scheme:dark;--bg:#070b12;--panel:#101827;--line:#263247;--text:#e6edf6;--muted:#8b98ad;--accent:#7dd3fc;--good:#34d399;--bad:#fb7185}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(1000px 700px at 80% -10%,#152744,var(--bg) 60%);color:var(--text);font-family:ui-sans-serif,system-ui,sans-serif}
main{width:min(1180px,calc(100% - 28px));margin:32px auto 80px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:24px}.brand{font-size:27px;font-weight:850;letter-spacing:.12em;color:var(--accent)}h1{font-size:24px;margin:0}h2{font-size:16px;margin:0 0 14px}.muted,.hint{color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.card{background:rgba(16,24,39,.92);border:1px solid var(--line);border-radius:15px;padding:18px;box-shadow:0 16px 50px #0005;margin-bottom:16px}.stat{font-size:28px;font-weight:800;margin-top:5px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}label{display:grid;gap:6px;color:var(--muted);font-size:13px;flex:1;min-width:190px}input,button,select{font:inherit;border-radius:9px;border:1px solid var(--line);padding:10px 12px;background:#0a111e;color:var(--text)}button{cursor:pointer;background:#18283f}button:hover{border-color:#5681ac}button.primary{background:#155e75;border-color:#0e7490}button.danger{background:#471b28;border-color:#7f1d35}.hidden{display:none!important}.error{color:var(--bad);white-space:pre-wrap}.success{color:var(--good)}.url{word-break:break-all;padding:12px;background:#080e18;border:1px solid var(--line);border-radius:9px;color:#bae6fd}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:10px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);font-weight:600}td{word-break:break-word}.scroll{overflow:auto;max-height:520px}.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:11px}.nav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}.nav button.active{border-color:var(--accent);color:var(--accent)}@media(max-width:620px){main{margin-top:18px}.card{padding:14px}th,td{padding:8px 6px}}
`;

function portalResponse(title: string, body: string, scriptPath: string): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>${PORTAL_STYLE}</style></head><body>${body}<script src="${scriptPath}" defer></script></body></html>`;
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  });
}

export function loginPortalPage(): Response {
  return portalResponse(
    'CHRTV — Secure M3U Login',
    `<main><div class="top"><div><div class="brand">CHRTV</div><div class="muted">Private playlist &amp; device management</div></div></div>
<section class="card" id="login-card"><h1>Secure M3U login</h1><p class="hint">Your password is sent via POST and never ends up in the playlist URL. The session link can be revoked at any time.</p>
<form id="login-form"><div class="grid"><label>Username<input name="username" autocomplete="username" required maxlength="128"></label><label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="256"></label><label>Device name<input name="device_name" placeholder="Living room TV" maxlength="80"></label></div><div class="row" style="margin-top:14px"><label style="display:flex;min-width:auto"><input name="replace_oldest" type="checkbox"> Revoke the oldest device when the session limit is reached</label><button class="primary" type="submit">Create M3U link</button></div></form><p id="login-error" class="error"></p></section>
<section class="card hidden" id="playlist-card"><h2>Playlist link for this device</h2><div id="playlist-url" class="url"></div><div class="row" style="margin-top:12px"><button id="copy-url">Copy link</button><button id="forget" class="danger">Remove token from this browser</button></div></section>
<section class="card hidden" id="sessions-card"><div class="top"><div><h2>Devices / login sessions</h2><div id="account-name" class="muted"></div></div><button id="refresh-sessions">Refresh</button></div><div class="scroll"><table><thead><tr><th>Device</th><th>Created / last IP</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody id="sessions-body"></tbody></table></div><p id="sessions-error" class="error"></p></section></main>`,
    '/ui/login.js',
  );
}

export function adminDashboardPage(): Response {
  return portalResponse(
    'CHRTV — Security Admin',
    `<main><div class="top"><div><div class="brand">CHRTV ADMIN</div><div class="muted">Security, users, sessions &amp; devices</div></div><div class="row"><input id="admin-token" type="password" autocomplete="current-password" placeholder="ADMIN_TOKEN"><button id="connect" class="primary">Connect</button><button id="logout">Clear token</button></div></div><p id="admin-error" class="error"></p>
<div id="dashboard" class="hidden"><div class="row" style="margin-bottom:14px"><button id="refresh">Refresh</button><button id="sync">Sync playlist</button></div><section class="grid" id="stats"></section>
<nav class="nav"><button data-tab="events" class="active">Login log</button><button data-tab="sessions">User sessions</button><button data-tab="bans">Security bans</button><button data-tab="users">Users</button><button data-tab="devices">Access-key devices</button></nav>
<section class="card tab" id="tab-events"><h2>Recent logins and playlist loads</h2><div class="scroll"><table><thead><tr><th>Time</th><th>User</th><th>IP</th><th>Event</th><th>Route</th><th>Outcome</th></tr></thead><tbody id="events-body"></tbody></table></div></section>
<section class="card tab hidden" id="tab-sessions"><h2>Revocable M3U sessions</h2><div class="scroll"><table><thead><tr><th>User</th><th>Device</th><th>IP</th><th>Last seen</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody id="admin-sessions-body"></tbody></table></div></section>
<section class="card tab hidden" id="tab-bans"><h2>Banned IP hashes</h2><div class="scroll"><table><thead><tr><th>Hash</th><th>Reason</th><th>Last seen</th><th>Expires</th><th>Hits</th><th></th></tr></thead><tbody id="bans-body"></tbody></table></div></section>
<section class="card tab hidden" id="tab-users"><h2>Users</h2><div class="scroll"><table><thead><tr><th>ID</th><th>Username</th><th>Status</th><th>Max sessions</th><th>Expires</th><th></th></tr></thead><tbody id="users-body"></tbody></table></div></section>
<section class="card tab hidden" id="tab-devices"><h2>Access-key devices / MAC</h2><div class="scroll"><table><thead><tr><th>ID</th><th>Key</th><th>MAC</th><th>First seen</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody id="devices-body"></tbody></table></div></section></div></main>`,
    '/ui/admin.js',
  );
}

const LOGIN_JS = String.raw`
const $=s=>document.querySelector(s);const escDate=v=>v?new Date(v*1000).toLocaleString():'Never expires';
let token=sessionStorage.getItem('chrtv_session')||'';let playlist=sessionStorage.getItem('chrtv_playlist')||'';
async function api(path,options={}){const headers={...(options.headers||{})};if(token)headers.Authorization='Bearer '+token;const r=await fetch(path,{...options,headers});let b={};try{b=await r.json()}catch{}if(!r.ok)throw new Error(b.error||('HTTP '+r.status));return b}
function td(tr,v){const e=document.createElement('td');e.textContent=String(v??'');tr.append(e);return e}
async function sessions(){if(!token)return;try{const data=await api('/api/account/sessions');$('#sessions-body').textContent='';$('#account-name').textContent=data.user.username+' · max '+data.user.max_connections+' sessions';for(const s of data.sessions){const tr=document.createElement('tr');td(tr,s.device_name||('Session '+s.token_prefix));td(tr,(s.ip_address||'—')+' / '+(s.last_ip||'—'));td(tr,escDate(s.last_seen));td(tr,s.id===data.current_session_id?s.status+' (current)':s.status);const a=td(tr,'');const b=document.createElement('button');b.textContent='Revoke';b.className='danger';b.disabled=s.status!=='active';b.onclick=async()=>{await api('/api/account/sessions/'+s.id,{method:'DELETE'});if(s.id===data.current_session_id){token='';sessionStorage.clear();location.reload()}else sessions()};a.append(b);$('#sessions-body').append(tr)}$('#sessions-card').classList.remove('hidden');$('#sessions-error').textContent=''}catch(e){$('#sessions-error').textContent=e.message}}
function show(){if(token&&playlist){$('#playlist-url').textContent=playlist;$('#playlist-card').classList.remove('hidden');sessions()}}
$('#login-form').onsubmit=async e=>{e.preventDefault();$('#login-error').textContent='';const f=new FormData(e.target);try{const data=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:f.get('username'),password:f.get('password'),device_name:f.get('device_name'),replace_oldest:f.get('replace_oldest')==='on'})});token=data.access_token;playlist=data.playlist_url;sessionStorage.setItem('chrtv_session',token);sessionStorage.setItem('chrtv_playlist',playlist);e.target.reset();show()}catch(x){$('#login-error').textContent=x.message}};
$('#copy-url').onclick=async()=>{await navigator.clipboard.writeText(playlist);$('#copy-url').textContent='Copied'};$('#refresh-sessions').onclick=sessions;$('#forget').onclick=()=>{sessionStorage.clear();location.reload()};show();
`;

const ADMIN_JS = String.raw`
const $=s=>document.querySelector(s);let token=sessionStorage.getItem('chrtv_admin')||'';$('#admin-token').value=token;const dt=v=>v?new Date(v*1000).toLocaleString():'—';
async function api(path,o={}){const r=await fetch(path,{...o,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(o.headers||{})}});let b={};try{b=await r.json()}catch{}if(!r.ok)throw new Error(b.error||('HTTP '+r.status));return b}function td(tr,v){const e=document.createElement('td');e.textContent=String(v??'');tr.append(e);return e}function btn(cell,label,fn,cls='danger'){const b=document.createElement('button');b.textContent=label;b.className=cls;b.onclick=fn;cell.append(b)}
function rows(id,data,render){const body=$(id);body.textContent='';for(const x of data){const tr=document.createElement('tr');render(tr,x);body.append(tr)}}
async function load(){try{const [st,events,sessions,bans,users,devices]=await Promise.all(['/api/admin/status','/api/admin/auth-events','/api/admin/sessions','/api/admin/security-bans','/api/admin/users','/api/admin/devices'].map(api));$('#admin-error').textContent='';$('#dashboard').classList.remove('hidden');const cards=[['Users',st.stats.users],['Active sessions',st.stats.active_sessions],['Login 24h',st.stats.auth_events_24h],['Bans',st.stats.active_security_bans],['Channels',st.playlist.channel_count||0]];$('#stats').textContent='';for(const [n,v] of cards){const c=document.createElement('section');c.className='card';const m=document.createElement('div');m.className='muted';m.textContent=n;const q=document.createElement('div');q.className='stat';q.textContent=v;c.append(m,q);$('#stats').append(c)}rows('#events-body',events,(tr,x)=>{td(tr,dt(x.created_at));td(tr,x.username||('user#'+(x.user_id||'—')));td(tr,x.ip_address||'—');td(tr,x.event_type);td(tr,x.route);td(tr,x.outcome)});rows('#admin-sessions-body',sessions,(tr,x)=>{td(tr,x.username);td(tr,x.device_name||x.token_prefix);td(tr,(x.ip_address||'—')+' / '+(x.last_ip||'—'));td(tr,dt(x.last_seen));td(tr,x.expires_at?dt(x.expires_at):'Never expires');td(tr,x.status);const c=td(tr,'');btn(c,'Revoke',async()=>{await api('/api/admin/sessions/'+x.id,{method:'DELETE'});load()})});rows('#bans-body',bans,(tr,x)=>{td(tr,x.ip_hash.slice(0,16)+'…');td(tr,x.reason);td(tr,dt(x.last_seen));td(tr,dt(x.expires_at));td(tr,x.hit_count);const c=td(tr,'');btn(c,'Unban',async()=>{await api('/api/admin/security-bans/'+x.ip_hash,{method:'DELETE'});load()})});rows('#users-body',users,(tr,x)=>{td(tr,x.id);td(tr,x.username);td(tr,x.status);td(tr,x.max_connections);td(tr,x.expires_at?dt(x.expires_at):'Never expires');const c=td(tr,'');btn(c,x.status==='active'?'Disable':'Enable',async()=>{await api('/api/admin/users/'+x.id,{method:'PATCH',body:JSON.stringify({status:x.status==='active'?'disabled':'active'})});load()},x.status==='active'?'danger':'');btn(c,'Max sessions',async()=>{const raw=prompt('Max sessions (1-100)',String(x.max_connections));if(raw===null)return;const n=Number(raw);if(!Number.isInteger(n)||n<1||n>100){alert('Value must be between 1 and 100');return}await api('/api/admin/users/'+x.id,{method:'PATCH',body:JSON.stringify({max_connections:n})});load()},'');btn(c,'Expiry',async()=>{const raw=prompt('Expiry time in ISO format, or leave empty for no expiry',x.expires_at?new Date(x.expires_at*1000).toISOString():'');if(raw===null)return;const expires_at=raw.trim()===''?null:Math.floor(Date.parse(raw)/1000);if(expires_at!==null&&!Number.isFinite(expires_at)){alert('Invalid date/time');return}await api('/api/admin/users/'+x.id,{method:'PATCH',body:JSON.stringify({expires_at})});load()},'')});rows('#devices-body',devices,(tr,x)=>{td(tr,x.id);td(tr,x.key_prefix);td(tr,x.mac_address);td(tr,dt(x.first_seen));td(tr,dt(x.last_seen));td(tr,x.status);const c=td(tr,'');btn(c,'Delete',async()=>{await api('/api/admin/devices/'+x.id,{method:'DELETE'});load()})})}catch(e){$('#admin-error').textContent=e.message;$('#dashboard').classList.add('hidden')}}
$('#connect').onclick=()=>{token=$('#admin-token').value.trim();sessionStorage.setItem('chrtv_admin',token);load()};$('#logout').onclick=()=>{sessionStorage.removeItem('chrtv_admin');location.reload()};$('#refresh').onclick=load;$('#sync').onclick=async()=>{try{await api('/api/admin/sync',{method:'POST'});load()}catch(e){$('#admin-error').textContent=e.message}};document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.tab').forEach(x=>x.classList.add('hidden'));$('#tab-'+b.dataset.tab).classList.remove('hidden')});if(token)load();
`;

export function portalScript(name: 'login' | 'admin'): Response {
  return new Response(name === 'login' ? LOGIN_JS : ADMIN_JS, {
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
