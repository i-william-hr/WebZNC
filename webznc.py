#!/usr/bin/env python3
"""
ZNC WebChat — single-user web client that keeps a persistent IRC/ZNC connection
and serves a dark, mobile-friendly UI over FastAPI + WebSocket.

- Persistent asyncio IRC client to ZNC (self-signed SSL ok)
- Channels list, nicklist (with modes), join/part/quit lines
- Send/receive, self-nick highlight, linkify, mIRC colors
- Plays back ZNC buffer on connect (requires 'playback' module)
- HTTP Basic OR ?auth=TOKEN (carried to WS via cookie)
- Optimized for mobile (prevents zoom on input focus)
- Can be run behind a reverse proxy on a subpath (e.g., /znc)
- Join a channel on connect via URL parameter (e.g., ?channel=help)

Quick start:
  pip3 install --upgrade fastapi "uvicorn[standard]"
  export ZNC_HOST='znc.example.com'
  export ZNC_PORT='6697'
  export ZNC_USER='user/network'
  export ZNC_PASS='password'
  export ZNC_NICK='webchat'
  # Either Basic Auth:
  export BASIC_USER='admin'; export BASIC_PASS='secret_password'
  # Or Token Auth:
  export AUTH_TOKEN='some_long_random_string'
  export HTTP_HOST='0.0.0.0'
  export HTTP_PORT='8080'
  python3 znc.py
"""

from __future__ import annotations
import asyncio, os, re, ssl, time, base64
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketState

# =======================
# Config (from environment variables)
# =======================
ZNC_HOST = os.getenv("ZNC_HOST", "127.0.0.1")
ZNC_PORT = int(os.getenv("ZNC_PORT", "6697"))
ZNC_USER = os.getenv("ZNC_USER", "user/network")
ZNC_PASS = os.getenv("ZNC_PASS", "password")
ZNC_NICK = os.getenv("ZNC_NICK", "webchat")

# Auth: HTTP Basic or token (?auth=TOKEN). If both empty, no auth.
BASIC_USER = os.getenv("BASIC_USER", "")
BASIC_PASS = os.getenv("BASIC_PASS", "")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")

# Web server
HTTP_HOST = os.getenv("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))

# History per channel
MAX_HISTORY = int(os.getenv("MAX_HISTORY", "200"))

# Reconnect strategy
RECONNECT_BASE = float(os.getenv("RECONNECT_BASE", "1.5"))
RECONNECT_MAX  = float(os.getenv("RECONNECT_MAX",  "60"))

# Allow invalid/self-signed SSL certs to ZNC
ALLOW_SELF_SIGNED = os.getenv("ALLOW_SELF_SIGNED", "1") == "1"

# =======================
# Auth helpers
# =======================
def require_auth(request: Request):
    token = request.query_params.get("auth") or request.cookies.get("auth_token")
    if token and AUTH_TOKEN and token == AUTH_TOKEN:
        return True
    if BASIC_USER and BASIC_PASS:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                userpw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "ignore")
                user, pw = userpw.split(":", 1)
                if user == BASIC_USER and pw == BASIC_PASS:
                    request.state.basic_ok = True
                    return True
            except Exception:
                pass
        raise HTTPException(status_code=401, detail="Auth required", headers={"WWW-Authenticate": "Basic"})
    if AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Auth token required. Append ?auth=KEY to URL.")
    return True

async def ws_require_auth(websocket: WebSocket):
    token = websocket.query_params.get("auth")
    cookie = websocket.headers.get("cookie") or websocket.headers.get("Cookie") or ""
    if AUTH_TOKEN and (token == AUTH_TOKEN or f"auth_token={AUTH_TOKEN}" in cookie):
        return True
    if BASIC_USER and BASIC_PASS:
        if "auth_ok=1" in cookie:
            return True
        proto = websocket.headers.get("Sec-WebSocket-Protocol")
        if proto:
            try:
                userpw = base64.b64decode(proto).decode()
                user, pw = userpw.split(":", 1)
                if user == BASIC_USER and pw == BASIC_PASS:
                    return True
            except Exception:
                pass
        await websocket.close(code=4401); return False
    if AUTH_TOKEN:
        await websocket.close(code=4401); return False
    return True

# =======================
# IRC/ZNC client
# =======================
IRC_COLOR_RE = re.compile(r"\x03(\d{1,2})(?:,(\d{1,2}))?")
URL_RE = re.compile(r"(https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+)")
MODE_PREFIX = {"@":"op","+":"voice","&":"admin","~":"owner","%":"halfop"}

@dataclass
class IrcMessage:
    ts: float; src: str; cmd: str; args: List[str]; raw: str

def parse_irc_line(line: str) -> IrcMessage:
    prefix = ""
    if line.startswith(":"):
        prefix, line = line[1:].split(" ", 1)
    if " :" in line:
        head, trailing = line.split(" :", 1)
        parts = head.split()
        cmd = parts[0]; args = parts[1:] + [trailing]
    else:
        parts = line.split()
        cmd = parts[0]; args = parts[1:]
    return IrcMessage(ts=time.time(), src=prefix, cmd=cmd, args=args, raw=line)

def mirc_to_html(text: str, own_nick: str) -> str:
    text = text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    text = IRC_COLOR_RE.sub(lambda m: f'<span class="irc-fg fg-{int(m.group(1))}">', text)
    text = text.replace("\x02","<b>").replace("\x1D","<i>").replace("\x1F","<u>").replace("\x0F","</span></b></i></u>")
    text = URL_RE.sub(r'<a href="\1" target="_blank" rel="noreferrer noopener">\1</a>', text)
    if own_nick:
        pattern = re.compile(rf"(?<![\w])({re.escape(own_nick)})(?![\w])", re.IGNORECASE)
        text = pattern.sub(r'<span class="self-nick">\1</span>', text)
    return text

class IRCClient:
    def __init__(self):
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = asyncio.Event()
        self.stop = False
        self.history: Dict[str, Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=MAX_HISTORY))
        self.nicklists: Dict[str, Dict[str, str]] = defaultdict(dict)
        self.channels: set[str] = set()
        self._ws_clients: set[WebSocket] = set()
        self.own_nick = ZNC_NICK

    def subscribe(self, ws: WebSocket): self._ws_clients.add(ws)
    def unsubscribe(self, ws: WebSocket): self._ws_clients.discard(ws)

    async def broadcast(self, payload: dict):
        dead = []
        for ws in list(self._ws_clients):
            try:
                if ws.application_state == WebSocketState.CONNECTED:
                    await ws.send_json(payload)
                else:
                    dead.append(ws)
            except Exception:
                dead.append(ws)
        for ws in dead: self.unsubscribe(ws)

    async def connect_loop(self):
        backoff = RECONNECT_BASE
        while not self.stop:
            try:
                ctx = ssl.create_default_context()
                if ALLOW_SELF_SIGNED:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                self.reader, self.writer = await asyncio.open_connection(ZNC_HOST, ZNC_PORT, ssl=ctx)
                await self.register()
                self.connected.set()
                await self.read_loop()
            except Exception as e:
                await self.broadcast({"type":"status","state":"disconnected","error":str(e)})
                await asyncio.sleep(backoff)
                backoff = min(RECONNECT_MAX, backoff*2)
            finally:
                self.connected.clear()
                try:
                    if self.writer:
                        self.writer.close()
                        await self.writer.wait_closed()
                except Exception:
                    pass

    async def register(self):
        pass_str = f"{ZNC_USER}:{ZNC_PASS}" if ":" not in ZNC_PASS else ZNC_PASS
        for line in [f"PASS {pass_str}", f"NICK {ZNC_NICK}", f"USER webchat 0 * :webchat"]:
            self.writer.write((line + "\r\n").encode())
        await self.writer.drain()
        await self.broadcast({"type":"status","state":"connecting"})

    async def read_loop(self):
        await self.broadcast({"type":"status","state":"connected"})
        while not self.stop:
            line = await self.reader.readline()
            if not line: raise ConnectionError("IRC connection closed")
            s = line.decode(errors="ignore").rstrip("\r\n")
            await self.handle(parse_irc_line(s))

    def _canon_chan(self, ch: str) -> Optional[str]:
        ch = ch.strip()
        if not ch.startswith("#"): return None
        ch = re.sub(r"[^#A-Za-z0-9_\-\[\]\\`^{}|]", "", ch)
        return ch[:50] or None

    async def handle(self, m: IrcMessage):
        if m.cmd == "PING":
            self.writer.write(f"PONG :{m.args[-1]}\r\n".encode()); await self.writer.drain(); return

        if m.cmd == "001":
            try: await self.send_raw('PRIVMSG *status :ListChans')
            except Exception: pass
            await self.broadcast({"type":"status","state":"ready"})
            for ch in sorted(list(self.channels)): await self.push_chan_update(ch)
            return

        if m.cmd in ("PRIVMSG","NOTICE"):
            nick = m.src.split("!")[0]
            target = m.args[0]
            text = m.args[1] if len(m.args) > 1 else ""

            if nick.lower() == "*status":
                mrow = re.match(r'^\|\s*\d+\s*\|\s*(#[^ \t|]+)\s*\|', text)
                chans: List[str] = [mrow.group(1)] if mrow else re.findall(r'(#[A-Za-z0-9_\-\[\]\\`^{}|]+)(?=[ \t|]|$)', text)
                added_any = False
                for raw in chans:
                    ch = self._canon_chan(raw)
                    if not ch: continue
                    if ch not in self.channels:
                        self.channels.add(ch); added_any = True
                        await self.send_raw(f"PRIVMSG *status :Attach {ch}")
                        await self.send_raw(f"NAMES {ch}")
                        await self.send_raw(f"PRIVMSG *playback :Play {ch}")
                if added_any:
                    for ch in sorted(list(self.channels)): await self.push_chan_update(ch)

            html = mirc_to_html(text, self.own_nick)
            chan = target if target.startswith("#") else nick
            self.append(chan, f"<span class='nick'>{nick}</span>: {html}")
            await self.push_chan_update(chan)
            return

        if m.cmd == "JOIN":
            nick = m.src.split("!")[0]; chan = m.args[0]
            self.channels.add(chan)
            if nick == self.own_nick: await self.send_raw(f"NAMES {chan}")
            self.append(chan, f"→ <span class='evt'>{nick} joined</span>")
            await self.push_chan_update(chan); return

        if m.cmd == "353" and len(m.args) >= 4:
            chan = m.args[2]; names = m.args[3].split(); nd = {}
            for n in names:
                mode = ""
                while n and n[0] in MODE_PREFIX: mode += MODE_PREFIX[n[0]] + ","; n = n[1:]
                nd[n] = mode.strip(",")
            self.nicklists[chan].update(nd); self.channels.add(chan)

        if m.cmd == "366" and len(m.args) >= 2:
            await self.push_chan_update(m.args[1]); return

        if m.cmd == "PART":
            nick = m.src.split("!")[0]; chan = m.args[0]
            self.append(chan, f"← <span class='evt'>{nick} left</span>")
            if nick == self.own_nick: self.channels.discard(chan); self.nicklists.pop(chan, None)
            else: self.nicklists.get(chan, {}).pop(nick, None)
            await self.push_chan_update(chan); return

        if m.cmd == "QUIT":
            nick = m.src.split("!")[0]
            for chan in list(self.channels):
                if nick in self.nicklists.get(chan, {}):
                    self.nicklists[chan].pop(nick, None)
                    self.append(chan, f"✖ <span class='evt'>{nick} quit</span>")
                    await self.push_chan_update(chan)
            return

        if m.cmd == "332" and len(m.args) >= 3:
            chan = m.args[1]; topic = m.args[2]
            self.append(chan, f"ℹ <span class='evt'>Topic:</span> {mirc_to_html(topic, self.own_nick)}")
            await self.push_chan_update(chan); return

    def append(self, chan: str, html: str):
        self.history[chan].append((time.time(), html))

    async def push_all(self):
        await self.broadcast({"type":"state","channels":sorted(list(self.channels)),"nicklists":self.nicklists})

    async def push_chan_update(self, chan: str):
        await self.broadcast({
            "type":"channel",
            "channel":chan,
            "history":list(self.history[chan]),
            "nicklist":self.nicklists.get(chan, {}),
            "channels":sorted(list(self.channels)),
        })

    async def send_raw(self, line: str):
        if not self.connected.is_set(): raise ConnectionError("Not connected")
        self.writer.write((line + "\r\n").encode()); await self.writer.drain()

    async def join(self, chan: str): await self.send_raw(f"JOIN {chan}")
    async def part(self, chan: str): await self.send_raw(f"PART {chan}")
    async def privmsg(self, target: str, text: str):
        await self.send_raw(f"PRIVMSG {target} :{text}")
        self.append(target, f"<span class='nick self'>{self.own_nick}</span>: {mirc_to_html(text, self.own_nick)}")
        await self.push_chan_update(target)

irc = IRCClient()

# =======================
# FastAPI + UI
# =======================
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

INDEX_HTML = """<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>ZNC WebChat</title>
<style>
:root { --bg:#0b0d10; --fg:#e8eef2; --muted:#9aa7b1; --accent:#5aa9ff; --panel:#12151a; --chip:#1a1f27; --border:#222832; }
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);font:14px -apple-system,BlinkMacSystemFont,Segoe UI,Inter,Roboto,Helvetica,Arial,sans-serif}
#app{display:flex;height:100dvh;gap:10px;padding:10px}
.sidebar{width:25%;max-width:340px;min-width:240px;background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:10px;display:flex;flex-direction:column}
.main{flex:1;background:var(--panel);border:1px solid var(--border);border-radius:16px;display:flex;flex-direction:column;min-width:0}
.hdr{padding:10px 12px;border-bottom:1px solid var(--border);font-weight:600}
.chan-list{overflow:auto;padding:8px;display:flex;flex-direction:column;gap:6px}
.chan{padding:8px 10px;border-radius:12px;background:var(--chip);cursor:pointer;display:flex;justify-content:space-between;align-items:center}
.chan.active{outline:2px solid var(--accent)}
.badge{background:var(--border);color:var(--muted);padding:2px 6px;border-radius:999px;font-size:12px}
.nicklist{overflow:auto;padding:8px 12px;display:flex;flex-direction:column;gap:4px;border-top:1px solid var(--border)}
.nick-item{padding: 2px 0;}
.nick{color:#cfe5ff;font-weight:600}.nick.self{color:#a0ffcf}.self-nick{background:#254;padding:0 2px;border-radius:3px}
.evt{color:var(--muted);font-style:italic}.log{flex:1;overflow:auto;padding:12px;line-height:1.35}
.msg{margin:6px 0;word-wrap:anywhere}.input{display:flex;gap:8px;padding:10px;border-top:1px solid var(--border)}
input[type=text]{flex:1;border-radius:10px;border:1px solid var(--border);padding:12px;background:#0f1318;color:var(--fg);font-size:16px}
button{background:var(--accent);color:#00101f;border:0;padding:10px 14px;border-radius:10px;font-weight:700}
.topbar{display:flex;gap:8px;align-items:center;padding:8px}.topbar input{flex:1}
.irc-fg{display:inline}.fg-0{color:#FFFFFF}.fg-1{color:#000000}.fg-2{color:#00007F}.fg-3{color:#009300}.fg-4{color:#FF0000}.fg-5{color:#7F0000}.fg-6{color:#9C009C}.fg-7{color:#FC7F00}.fg-8{color:#FFFF00}.fg-9{color:#00FC00}.fg-10{color:#009393}.fg-11{color:#00FFFF}.fg-12{color:#0000FC}.fg-13{color:#FF00FF}.fg-14{color:#7F7F7F}.fg-15{color:#D2D2D2}
@media (max-width: 900px) {
    #app { flex-direction: column; }
    .main { order: 1; flex: 1; min-height: 0; }
    .sidebar { order: 2; width: 100%; max-width: none; min-width: unset; height: 40vh; min-height: 220px; }
    .sidebar .chan-list, .sidebar .nicklist { flex: 1; }
}
</style></head>
<body><div id="app">
  <div class="main">
    <div class="hdr" id="title">ZNC WebChat</div>
    <div class="log" id="log"></div>
    <div class="input">
      <input id="msg" type="text" placeholder="Message…  (/join #chan, /part, /me …)" autocomplete="off">
      <button id="send">Send</button>
    </div>
  </div>
  <div class="sidebar">
    <div class="topbar">
      <input id="joinname" type="text" placeholder="#channel to join" autocomplete="off">
      <button id="joinbtn">Join</button>
    </div>
    <div class="hdr">Channels</div>
    <div class="chan-list" id="chans"></div>
    <div class="hdr">Nicklist</div>
    <div class="nicklist" id="nicks"></div>
  </div>
</div>
<script>
let WS; let ACTIVE=null; let STATE={channels:[],histories:{},nicks:{}};
const urlParams = new URLSearchParams(window.location.search);
const initialChannel = urlParams.get('channel');
if (initialChannel) {
    ACTIVE = initialChannel.startsWith('#') ? initialChannel : '#' + initialChannel;
}
function wsUrl(){const loc=window.location; const proto=(loc.protocol==='https:')?'wss':'ws'; const auth=new URLSearchParams(loc.search).get('auth'); let u=`${proto}://${loc.host}${loc.pathname}ws`; if(auth) u+=`?auth=${encodeURIComponent(auth)}`; return u.replace('//ws', '/ws');}
function connect(){ WS=new WebSocket(wsUrl()); WS.onopen=()=>console.log('ws open'); WS.onmessage=(ev)=>handle(JSON.parse(ev.data)); WS.onclose=()=>setTimeout(connect,1500); }
function handle(msg){
  if(msg.type==='status'){ document.getElementById('title').textContent=`ZNC WebChat — ${msg.state}`; return; }
  if(msg.type==='state'){ STATE.channels=msg.channels; renderChannels(); return; }
  if(msg.type==='channel'){
    let wasAtBottom = true;
    const logEl = document.getElementById('log');
    if (logEl) { wasAtBottom = logEl.scrollHeight - logEl.clientHeight <= logEl.scrollTop + 1; }
    if(msg.channels) STATE.channels=msg.channels;
    if(msg.history) STATE.histories[msg.channel]=msg.history;
    if(msg.nicklist) STATE.nicks[msg.channel]=msg.nicklist;
    if(!ACTIVE && msg.channel && msg.channel.startsWith('#')) ACTIVE=msg.channel;
    renderChannels();
    if(msg.channel===ACTIVE){ renderLog(ACTIVE, wasAtBottom); renderNicks(ACTIVE);}
    return;
  }
}
function send(o){ WS.send(JSON.stringify(o)); }
function renderChannels(){ const el=document.getElementById('chans'); el.innerHTML=''; STATE.channels.forEach(c=>{ const d=document.createElement('div'); d.className='chan'+(c===ACTIVE?' active':''); d.textContent=c; const b=document.createElement('span'); b.className='badge'; b.textContent=(STATE.histories[c]||[]).length; d.appendChild(b); d.onclick=()=>{ ACTIVE=c; renderChannels(); renderLog(c, true); renderNicks(c); }; el.appendChild(d); }); }
function renderLog(chan, scroll){ const list=STATE.histories[chan]||[]; const el=document.getElementById('log'); el.innerHTML=list.map(([ts,html])=>`<div class="msg" data-ts="${ts}">${html}</div>`).join(''); if(scroll) el.scrollTop=el.scrollHeight; document.getElementById('title').textContent=chan+' — ZNC WebChat'; }
function renderNicks(chan){ const el=document.getElementById('nicks'); const nl=STATE.nicks[chan]||{}; el.innerHTML=''; Object.keys(nl).sort((a,b)=>a.localeCompare(b,undefined,{sensitivity:'base'})).forEach(n=>{ const item=document.createElement('div'); item.className='nick-item'; const mode=nl[n]?` [${nl[n]}]`:''; item.innerHTML=`<span class="nick">${n}</span>${mode}`; el.appendChild(item); }); }
document.getElementById('send').onclick=sendMessage;
document.getElementById('msg').addEventListener('keydown',e=>{ if(e.key==='Enter') sendMessage(); });
function sendMessage(){ const inp=document.getElementById('msg'); const text=inp.value.trim(); if(!text) return;
  if(text.startsWith('/')){ const [cmd,...rest]=text.slice(1).split(' '); const cmdLower = cmd.toLowerCase();
    if(cmdLower==='join') send({type:'join',channel:rest[0]});
    else if (cmdLower==='part') send({type:'part',channel:rest.length > 0 ? rest.join(' ') : ACTIVE});
    else if (cmdLower==='me') send({type:'msg',target:ACTIVE,text:`\x01ACTION ${rest.join(' ')}\x01`});
    else send({type:'raw',line:text.slice(1)}); }
  else { send({type:'msg',target:ACTIVE,text}); }
  inp.value=''; }
document.getElementById('joinbtn').onclick=()=>{ const v=document.getElementById('joinname').value.trim(); if(v) { send({type:'join',channel:v}); document.getElementById('joinname').value=''; } };
connect();
</script>
</body></html>"""

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def index(request: Request):
    require_auth(request)
    resp = HTMLResponse(INDEX_HTML)
    token = request.query_params.get("auth")
    if token and AUTH_TOKEN and token == AUTH_TOKEN:
        resp.set_cookie("auth_token", token, httponly=True, samesite="lax")
    if getattr(request.state, "basic_ok", False):
        resp.set_cookie("auth_ok", "1", httponly=False, samesite="lax")
    return resp

@app.websocket("/{subpath:path}ws")
async def ws(websocket: WebSocket):
    ok = await ws_require_auth(websocket)
    if not ok: return
    await websocket.accept()
    irc.subscribe(websocket)
    try:
        channel_to_join = websocket.query_params.get("channel")
        if channel_to_join:
            if not channel_to_join.startswith("#"):
                channel_to_join = "#" + channel_to_join
            await irc.join(channel_to_join)

        try: await irc.send_raw('PRIVMSG *status :ListChans')
        except Exception: pass

        await irc.push_all()
        for ch in sorted(list(irc.channels)): await irc.push_chan_update(ch)

        while True:
            msg = await websocket.receive_json()
            typ = msg.get("type")
            if   typ == "join": await irc.join(msg.get("channel", ""))
            elif typ == "part": await irc.part(msg.get("channel", ""))
            elif typ == "msg":  await irc.privmsg(msg.get("target", ""), msg.get("text", ""))
            elif typ == "raw":  await irc.send_raw(msg.get("line", ""))
    except WebSocketDisconnect:
        pass
    finally:
        irc.unsubscribe(websocket)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(irc.connect_loop())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HTTP_HOST, port=HTTP_PORT, reload=False, workers=1)
