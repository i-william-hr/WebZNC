import threading
import time
import ssl
import sys
import os
import collections
import logging
import html
import re
from flask import Flask, render_template_string, request, redirect, url_for, jsonify, Response

import irc.client
import irc.connection

# ==========================================
# 1. CONFIGURATION
# ==========================================
# Read from .env (0600, owned by webznc, read by systemd via EnvironmentFile=
# in webznc.service). Defaults are the values that were previously hardcoded.
#
# This is the ZNC admin account and the same personal IRC identity the operator
# uses elsewhere, so ZNC_PASS is a real credential and lives in the 0600 file
# rather than here. Rotated 2026-09-30. ZNC_USER/IRC_NICK are the same identity;
# both default to "" here and are set in .env (see .env.example).
ZNC_HOST = os.environ.get("ZNC_HOST", "127.0.0.1")
ZNC_PORT = int(os.environ.get("ZNC_PORT", "9999"))
ZNC_SSL_ENABLED = os.environ.get("ZNC_SSL_ENABLED", "1") == "1"
ZNC_USER = os.environ.get("ZNC_USER", "")
ZNC_NET = os.environ.get("ZNC_NET", "Rizon")
ZNC_PASS = os.environ.get("ZNC_PASS", "")
IRC_NICK = os.environ.get("IRC_NICK", "")

# ZNC presents a self-signed certificate, so verification is currently off.
# Turning it on requires replacing znc.pem with a certificate that chains to a
# trusted root -- do it in ZNC, then set this to 0.
WEBZNC_SSL_NO_VERIFY = os.environ.get("WEBZNC_SSL_NO_VERIFY", "1") == "1"

# Authentication: none in here. nginx gates /znc with an auth_request
# subrequest against the SSO app (proxy-webznc.conf), so the sso cookie is the
# only credential the web UI has. The ZNC_*/IRC_NICK values above are a
# separate thing entirely -- that is how this app logs in to the bouncer, and
# it is not reachable from the browser.

FLASK_PORT = int(os.environ.get("FLASK_PORT", "7006"))

# Limits. IRC caps a wire line at 512 bytes including CR/LF, and the
# ":nick!user@host PRIVMSG #chan :" prefix eats ~60 of them. Refuse overlong
# input at the edge instead of letting send_raw() raise deep in the send path.
MAX_MESSAGE_BYTES = int(os.environ.get("MAX_MESSAGE_BYTES", "400"))
MAX_TOPIC_BYTES = int(os.environ.get("MAX_TOPIC_BYTES", "300"))
MAX_MESSAGES = int(os.environ.get("MAX_MESSAGES", "1000"))

RECONNECT_DELAY = int(os.environ.get("RECONNECT_DELAY", "5"))

LOG_LEVEL = os.environ.get('WEBZNC_LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format='%(asctime)s %(levelname)s %(message)s',
                    stream=sys.stdout)
log = logging.getLogger('webznc')

# ==========================================
# 2. PROXY MIDDLEWARE
# ==========================================
class ReverseProxied(object):
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        script_name = environ.get('HTTP_X_SCRIPT_NAME', '')
        if script_name:
            environ['SCRIPT_NAME'] = script_name
            path_info = environ.get('PATH_INFO', '')
            if path_info.startswith(script_name):
                environ['PATH_INFO'] = path_info[len(script_name):]
        return self.app(environ, start_response)

# ==========================================
# 3. STATE MANAGEMENT & PARSING
# ==========================================
# STATE and CHANNELS_DISPLAY are written by the IRC reactor thread and read by
# Flask worker threads, so every access goes through STATE_LOCK. The old
# defaultdict self-vivified an entry for any target a caller merely mentioned,
# which let a stray poll URL grow memory without bound.
STATE_LOCK = threading.RLock()
STATE = {}
CHANNELS_DISPLAY = {}

# python-irc's send_raw() takes no lock of its own, but the reactor thread
# auto-replies to PINGs while Flask threads may be sending PRIVMSG/PART. Two
# concurrent writers can interleave mid-line and corrupt the stream, so every
# socket write funnels through here.
IRC_SEND_LOCK = threading.RLock()

# Handed back for unknown targets: readable, never inserted into STATE.
EMPTY_STATE = {'messages': (), 'nicks': (), 'topic': ''}

_SEQ_LOCK = threading.Lock()
_SEQ = 0


def next_seq():
    """Monotonic id for each stored message.

    The browser tracks the highest seq it has rendered instead of comparing
    list lengths, so a full buffer rolling over no longer freezes live updates.
    """
    global _SEQ
    with _SEQ_LOCK:
        _SEQ += 1
        return _SEQ


def writable_state(key):
    with STATE_LOCK:
        st = STATE.get(key)
        if st is None:
            st = {'messages': collections.deque(maxlen=MAX_MESSAGES),
                  'nicks': [], 'topic': ''}
            STATE[key] = st
        return st


def readable_state(key):
    with STATE_LOCK:
        return STATE.get(key, EMPTY_STATE)


def channel_list():
    with STATE_LOCK:
        return [CHANNELS_DISPLAY[k] for k in CHANNELS_DISPLAY]


def remember_channel(key, display):
    """Record a target as seen, and mark it most-recently-active.

    Re-inserting an existing key moves it to the end, which is what index()
    uses to pick where to land. Views deliberately do not call this: a URL is
    not evidence that a target exists, and writing here is what used to leave
    phantom channels in the sidebar after a typo.
    """
    with STATE_LOCK:
        CHANNELS_DISPLAY.pop(key, None)
        CHANNELS_DISPLAY[key] = display


def forget_channel(key):
    with STATE_LOCK:
        CHANNELS_DISPLAY.pop(key, None)


def most_recent_channel():
    with STATE_LOCK:
        for key in reversed(list(CHANNELS_DISPLAY)):
            return key, CHANNELS_DISPLAY[key]
    return None, None


URL_RE = re.compile(r'(https?://[^\s<>"\'\x00-\x1F]+|www\.[^\s<>"\'\x00-\x1F]+)')
COLOR_RE = re.compile(r'^(\d{1,2})(?:,(\d{1,2}))?')

IRC_COLORS = [
    '#ffffff', '#000000', '#00007f', '#009300',
    '#ff0000', '#7f0000', '#9c009c', '#fc7f00',
    '#ffff00', '#00fc00', '#009393', '#00ffff',
    '#0000fc', '#ff00ff', '#7f7f7f', '#d2d2d2'
]

NICK_PREFIXES = '@+~&%!'


def parse_irc_message(text):
    # 1. Escape HTML to prevent XSS
    escaped_text = html.escape(text)

    # 2. Make Links Clickable
    def url_repl(match):
        url = match.group(1)
        href = url if url.startswith('http') else 'http://' + url
        return f'<a href="{href}" target="_blank" rel="noopener noreferrer" style="color:var(--accent); text-decoration:underline;">{url}</a>'

    escaped_text = URL_RE.sub(url_repl, escaped_text)

    # 3. IRC Colors and Formatting
    out = []
    i = 0
    bold = italic = underline = color_open = False

    while i < len(escaped_text):
        c = escaped_text[i]
        if c == '\x02':  # Bold
            out.append("</b>" if bold else "<b>")
            bold = not bold
        elif c == '\x1f':  # Underline
            out.append("</u>" if underline else "<u>")
            underline = not underline
        elif c == '\x1d':  # Italic
            out.append("</i>" if italic else "<i>")
            italic = not italic
        elif c == '\x0f':  # Reset
            if bold:
                out.append("</b>"); bold = False
            if underline:
                out.append("</u>"); underline = False
            if italic:
                out.append("</i>"); italic = False
            if color_open:
                out.append("</span>"); color_open = False
        elif c == '\x03':  # Color
            m = COLOR_RE.match(escaped_text[i+1:i+7])
            if m:
                i += len(m.group(0))
                style = ""
                fg = int(m.group(1))
                if 0 <= fg <= 15:
                    style += f"color: {IRC_COLORS[fg]};"
                if m.group(2):
                    bg = int(m.group(2))
                    if 0 <= bg <= 15:
                        style += f"background-color: {IRC_COLORS[bg]};"
                if color_open:
                    out.append("</span>")
                if style:
                    out.append(f"<span style='{style}'>")
                    color_open = True
                else:
                    color_open = False
            else:
                if color_open:
                    out.append("</span>")
                    color_open = False
        else:
            out.append(c)
        i += 1

    if bold:
        out.append("</b>")
    if underline:
        out.append("</u>")
    if italic:
        out.append("</i>")
    if color_open:
        out.append("</span>")

    return "".join(out)


def irc_send(fn, *args, **kwargs):
    """Serialize a write to the IRC socket."""
    with IRC_SEND_LOCK:
        return fn(*args, **kwargs)


def connected():
    return client.connection is not None and client.connection.is_connected()


def current_nick():
    if connected():
        return client.connection.get_nickname() or IRC_NICK
    return IRC_NICK


# ==========================================
# 4. IRC CLIENT
# ==========================================
class ZNCClient(irc.client.SimpleIRCClient):
    def __init__(self):
        super().__init__()
        self._echo_lock = threading.Lock()
        self._pending_echo = collections.deque(maxlen=50)

    def _note_sent(self, text):
        """Remember a line we just sent.

        ZNC replays our own messages back to the attached client. The previous
        code instead dropped any message identical to the previous one, which
        also silently swallowed a user genuinely repeating themselves.
        """
        with self._echo_lock:
            self._pending_echo.append(text)

    def _discard_sent(self, text):
        with self._echo_lock:
            try:
                self._pending_echo.remove(text)
            except ValueError:
                pass

    def _consume_echo(self, text):
        with self._echo_lock:
            if self._pending_echo and self._pending_echo[0] == text:
                self._pending_echo.popleft()
                return True
        return False

    def on_welcome(self, connection, event):
        log.info("[IRC] Connected to ZNC as %s", current_nick())
        log.info("[IRC] Requesting PlayBuffer * from *status")
        irc_send(connection.privmsg, "*status", "PlayBuffer *")

    def on_disconnect(self, connection, event):
        reason = event.arguments[0] if event.arguments else 'Unknown'
        log.info("[IRC] Disconnected: %s", reason)
        sys.exit(0)

    def on_join(self, connection, event):
        raw_target = event.target
        key = raw_target.lower()
        nick = event.source.nick
        remember_channel(key, raw_target)
        writable_state(key)
        self._add_msg(key, "-->", f"{nick} has joined {raw_target}")
        if nick == current_nick():
            irc_send(connection.mode, raw_target, "")

    def on_part(self, connection, event):
        raw_target = event.target
        key = raw_target.lower()
        nick = event.source.nick
        if nick == current_nick():
            forget_channel(key)
        else:
            with STATE_LOCK:
                nicks = readable_state(key)['nicks']
                if nick in nicks:
                    nicks.remove(nick)
        self._add_msg(key, "<--", f"{nick} has left {raw_target}")

    def on_quit(self, connection, event):
        nick = event.source.nick
        reason = event.arguments[0] if event.arguments else 'Connection closed'
        with STATE_LOCK:
            affected = [k for k, st in STATE.items() if nick in st['nicks']]
            for k in affected:
                STATE[k]['nicks'].remove(nick)
        for k in affected:
            self._add_msg(k, "<--", f"{nick} has quit ({reason})")

    def on_kick(self, connection, event):
        raw_target = event.target
        key = raw_target.lower()
        victim = event.arguments[0] if event.arguments else ''
        reason = event.arguments[1] if len(event.arguments) > 1 else current_nick()
        self._add_msg(key, "<--", f"{victim} was kicked ({reason})")
        with STATE_LOCK:
            st = STATE.get(key)
            if st and victim in st['nicks']:
                st['nicks'].remove(victim)
        if victim == current_nick():
            forget_channel(key)

    def on_nick(self, connection, event):
        old = event.source.nick
        new = event.arguments[0] if event.arguments else old
        with STATE_LOCK:
            for st in STATE.values():
                if old in st['nicks']:
                    st['nicks'][st['nicks'].index(old)] = new
            if not old.startswith('#') and old.lower() in CHANNELS_DISPLAY:
                # An open private-query window should follow the rename.
                CHANNELS_DISPLAY.pop(old.lower(), None)
                moved = STATE.pop(old.lower(), None)
                if moved is not None:
                    STATE[new.lower()] = moved
                CHANNELS_DISPLAY[new.lower()] = new
                if new.lower() in CHANNELS_DISPLAY:
                    CHANNELS_DISPLAY[new.lower()] = new

    def on_pubmsg(self, connection, event):
        raw_target = event.target
        key = raw_target.lower()
        msg_text = event.arguments[0]
        log.debug("[MSG IN] %s <%s> %s", raw_target, event.source.nick, msg_text)

        if event.source.nick == current_nick() and self._consume_echo(msg_text):
            return

        remember_channel(key, raw_target)
        self._add_msg(key, event.source.nick, msg_text)

    def on_privmsg(self, connection, event):
        sender = event.source.nick
        key = sender.lower()
        msg_text = event.arguments[0]
        log.debug("[PM IN] %s <%s> %s", sender, sender, msg_text)

        if sender == current_nick() and self._consume_echo(msg_text):
            return

        remember_channel(key, sender)
        self._add_msg(key, sender, msg_text)

    def _set_topic(self, key, topic, display=None):
        with STATE_LOCK:
            writable_state(key)['topic'] = topic[:MAX_TOPIC_BYTES]
        if display:
            remember_channel(key, display)

    def on_currenttopic(self, connection, event):
        self._set_topic(event.arguments[0].lower(), event.arguments[1],
                        event.arguments[0])

    def on_topic(self, connection, event):
        raw_target = event.target
        self._set_topic(raw_target.lower(), event.arguments[0], raw_target)
        self._add_msg(raw_target.lower(), "***", f"Topic changed to: {event.arguments[0]}")

    def on_namreply(self, connection, event):
        raw_target = event.arguments[1]
        key = raw_target.lower()
        clean_names = []
        for n in event.arguments[2].split():
            stripped = n.lstrip(NICK_PREFIXES)
            if stripped:
                clean_names.append(stripped)
        with STATE_LOCK:
            writable_state(key)['nicks'] = sorted(clean_names)
        remember_channel(key, raw_target)

    def _add_msg(self, key, user, text):
        key = key.lower()
        msg = {
            'seq': next_seq(),
            'time': time.strftime("%H:%M"),
            'user': user,
            'text': text,
            'html': parse_irc_message(text),
        }
        with STATE_LOCK:
            writable_state(key)['messages'].append(msg)

    def connect_znc(self):
        """One connection attempt.

        Retries live in irc_thread_run(). This used to call itself on failure,
        so a long ZNC outage stacked a stack frame per attempt until the
        thread died of RecursionError.
        """
        password_string = f"{ZNC_USER}/{ZNC_NET}:{ZNC_PASS}"
        if ZNC_SSL_ENABLED:
            context = ssl.create_default_context()
            if WEBZNC_SSL_NO_VERIFY:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            def ssl_wrapper(sock, server_hostname=ZNC_HOST):
                return context.wrap_socket(sock, server_hostname=server_hostname)
            connect_factory = irc.connection.Factory(wrapper=ssl_wrapper)
        else:
            connect_factory = irc.connection.Factory()

        log.info("[IRC] Connecting to %s:%s", ZNC_HOST, ZNC_PORT)
        self.connect(ZNC_HOST, ZNC_PORT, IRC_NICK, password=password_string,
                     connect_factory=connect_factory)

client = ZNCClient()


# --- THREAD RUNNER ---
def irc_thread_run():
    while True:
        try:
            client.connect_znc()
            client.start()
        except SystemExit:
            log.info("[IRC] Connection ended, retrying in %ss", RECONNECT_DELAY)
        except Exception as e:
            log.error("[IRC] Connection failed: %s", e)
        time.sleep(RECONNECT_DELAY)

t = threading.Thread(target=irc_thread_run, name='irc', daemon=True)
t.start()

# ==========================================
# 5. FLASK APPLICATION
# ==========================================
app = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)

# No app.secret_key and no session: the app keeps no state between requests,
# so there is nothing for one to sign.
app.config.update(JSON_SORT_KEYS=False)


def _render(state_key, true_target):
    """Render a channel or query.

    state_key is the STATE lookup key, which for channels includes the leading
    '#' because that is how the IRC handlers register them. The browser, by
    contrast, polls without the '#' and relies on the fallback in poll_state.
    """
    with STATE_LOCK:
        st = STATE.get(state_key, EMPTY_STATE)
        messages = list(st['messages'])
        nicks = list(st['nicks'])
        topic = st['topic']
    return render_template_string(
        HTML_TEMPLATE,
        true_target=true_target,
        messages=messages,
        last_seq=messages[-1]['seq'] if messages else 0,
        channels=channel_list(),
        nicks=nicks,
        topic=topic)


@app.route('/')
def index():
    _, display_name = most_recent_channel()
    if display_name:
        if display_name.startswith('#'):
            return redirect(url_for('channel_view', name=display_name[1:]))
        return redirect(url_for('query_view', name=display_name))
    return render_template_string(
        HTML_TEMPLATE, true_target="status",
        messages=[{'seq': 0, 'time': '--', 'user': 'System',
                   'text': 'Connected. History requested...',
                   'html': 'Connected. History requested...'}],
        last_seq=0, channels=[], nicks=[], topic="")


@app.route('/channel/<path:name>')
def channel_view(name):
    display_target = name if name.startswith('#') else '#' + name
    return _render(display_target.lower(), display_target)


@app.route('/query/<path:name>')
def query_view(name):
    display_target = name.replace('#', '')
    return _render(display_target.lower(), display_target)


@app.route('/api/send', methods=['POST'])
def send_message():
    target = request.form.get('target', '')
    message = request.form.get('message', '')

    if not message or not target:
        return jsonify({'status': 'error', 'error': 'Nothing to send'}), 400
    if len(message.encode('utf-8')) > MAX_MESSAGE_BYTES:
        return jsonify({'status': 'error',
                        'error': f'Message too long (max {MAX_MESSAGE_BYTES} bytes)'}), 400
    # Previously the local echo was added and a "ok" returned even when the
    # socket was down, so a dropped message looked exactly like a sent one.
    if not connected():
        return jsonify({'status': 'error',
                        'error': 'Not connected to IRC - message was NOT sent'}), 503

    my_nick = current_nick()
    key = target.lower()

    try:
        if message.startswith('/'):
            parts = message.split(' ')
            cmd = parts[0].lower()
            if cmd == '/msg' and len(parts) >= 3:
                user = parts[1]
                msg_text = ' '.join(parts[2:])
                irc_send(client.connection.privmsg, user, msg_text)
                client._note_sent(msg_text)
                client._add_msg(user.lower(), my_nick, msg_text)
                remember_channel(user.lower(), user)
            elif cmd == '/query' and len(parts) >= 2:
                return jsonify({'status': 'redirect',
                                'url': url_for('query_view', name=parts[1])})
            elif cmd == '/topic' and len(parts) > 1:
                irc_send(client.connection.topic, target,
                         ' '.join(parts[1:])[:MAX_TOPIC_BYTES])
            elif cmd == '/join' and len(parts) >= 2:
                chan = parts[1]
                if not chan.startswith('#'):
                    chan = '#' + chan
                irc_send(client.connection.join, chan)
                return jsonify({'status': 'redirect',
                                'url': url_for('channel_view', name=chan[1:])})
            elif cmd == '/part':
                irc_send(client.connection.part, target)
                forget_channel(key)
                return jsonify({'status': 'redirect',
                                'url': url_for('index')})
            elif cmd == '/me' and len(parts) >= 2:
                action_text = ' '.join(parts[1:])
                irc_send(client.connection.action, target, action_text)
                client._note_sent(action_text)
                client._add_msg(key, "* " + my_nick, action_text)
            else:
                return jsonify({'status': 'error',
                                'error': f'Unknown command: {cmd}'}), 400
        else:
            irc_send(client.connection.privmsg, target, message)
            client._note_sent(message)
            client._add_msg(key, my_nick, message)
    except Exception as e:
        client._discard_sent(message)
        log.error("[SEND ERROR] %s", e)
        return jsonify({'status': 'error', 'error': f'Send failed: {e}'}), 502

    return jsonify({'status': 'ok'})


@app.route('/api/join', methods=['POST'])
def join_channel():
    channel = request.form.get('channel', '')
    if channel and not channel.startswith('#'):
        channel = '#' + channel
    if not channel or not connected():
        return redirect(url_for('index'))
    irc_send(client.connection.join, channel)
    # Not recorded here: on_join registers it once the server confirms, so a
    # failed join leaves no phantom entry.
    return redirect(url_for('channel_view', name=channel[1:]))


@app.route('/api/poll/<path:name>')
def poll_state(name):
    key = name.lower()
    with STATE_LOCK:
        if key not in STATE and ('#' + key) in STATE:
            key = '#' + key
        st = STATE.get(key, EMPTY_STATE)
        messages = list(st['messages'])
        nicks = list(st['nicks'])
        topic = st['topic']
        channels = [CHANNELS_DISPLAY[k] for k in CHANNELS_DISPLAY]
    return jsonify({
        'messages': messages,
        'topic': topic,
        'nicks': nicks,
        'channels': channels,
    })


# ==========================================
# 6. FRONTEND TEMPLATE
# ==========================================
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZNC WebChat</title>
    <style>
        :root { --bg-dark: #121317; --bg-panel: #1a1b21; --border: #2c2e36; --text-main: #e0e0e0; --text-dim: #888; --accent: #5c9df5; --accent-hover: #4a8ce2; --danger: #ff6b6b; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg-dark); color: var(--text-main); height: 100vh; overflow: hidden; display: flex; flex-direction: column; }
        .app-container { display: flex; flex: 1; height: 100%; overflow: hidden; }
        .main-area { flex: 1; display: flex; flex-direction: column; border-right: 1px solid var(--border); min-width: 0; }
        .header { padding: 10px 15px; border-bottom: 1px solid var(--border); font-size: 14px; font-weight: bold; background: var(--bg-panel); display: flex; justify-content: space-between; }
        .topic { font-weight: normal; font-size: 12px; color: var(--text-dim); margin-left: 10px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .chat-history { flex: 1; overflow-y: auto; padding: 15px; background: var(--bg-dark); display: flex; flex-direction: column; gap: 4px; }
        .msg { font-size: 14px; line-height: 1.4; word-wrap: break-word; }
        .msg .time { color: var(--text-dim); font-size: 11px; margin-right: 8px; display: inline-block; width: 35px; }
        .msg .user { font-weight: bold; color: #aaddff; margin-right: 5px; }
        .msg .text { color: #ddd; }
        .status-line { padding: 0 12px; font-size: 12px; color: var(--danger); background: var(--bg-panel); }
        .status-line:empty { display: none; }
        .input-area { padding: 10px; background: var(--bg-panel); border-top: 1px solid var(--border); display: flex; gap: 10px; }
        .input-area input { flex: 1; background: #0f1013; border: 1px solid var(--border); color: white; padding: 10px; border-radius: 6px; outline: none; font-size: 16px; }
        .input-area button { background: var(--accent); color: white; border: none; padding: 0 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }
        .input-area button:hover { background: var(--accent-hover); }
        .input-area button:disabled { opacity: 0.5; cursor: default; }
        .sidebar { width: 300px; background: var(--bg-panel); display: flex; flex-direction: column; overflow-y: auto; }
        .sidebar-section { padding: 15px; border-bottom: 1px solid var(--border); }
        .sidebar-title { font-size: 12px; font-weight: bold; color: var(--text-dim); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
        .join-box { display: flex; gap: 5px; }
        .join-box input { flex: 1; background: #0f1013; border: 1px solid var(--border); padding: 6px; color: white; border-radius: 4px; font-size: 16px; }
        .join-box button { background: var(--accent); color: white; border: none; padding: 0 12px; border-radius: 4px; cursor: pointer; }
        .list-item { display: block; padding: 6px 10px; color: #bbb; text-decoration: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .list-item:hover { background: #2a2b33; color: white; }
        .list-item.active { background: #2a2b33; color: white; font-weight: bold; border-left: 3px solid var(--accent); }
        .nick-item { cursor: pointer; color: #bbb; }
        @media (max-width: 768px) {
            .app-container { flex-direction: column; }
            .sidebar { width: 100%; height: 40%; border-top: 1px solid var(--border); order: 2; }
            .main-area { height: 60%; order: 1; border-right: none; }
        }
    </style>
</head>
<body>
<div class="app-container">
    <div class="main-area">
        <div class="header">
            <span>{{ true_target }}</span>
            <span class="topic" id="topic-display">{{ topic }}</span>
        </div>
        <div class="chat-history" id="chat-box">
            {% for msg in messages %}
                <div class="msg"><span class="time">{{ msg.time }}</span><span class="user">{{ msg.user }}</span><span class="text">{{ msg.html | safe }}</span></div>
            {% endfor %}
        </div>
        <div class="status-line" id="status-line"></div>
        <div class="input-area">
            <input type="text" id="msg-input" placeholder="Message... (/join #chan, /part, /me ...)" autocomplete="off" autofocus>
            <button type="button" id="send-btn" onclick="sendMessage()">Send</button>
        </div>
    </div>
    <div class="sidebar">
        <div class="sidebar-section">
            <form action="{{ url_for('join_channel') }}" method="POST" class="join-box">
                <input type="text" name="channel" placeholder="#channel to join">
                <button type="submit">Join</button>
            </form>
        </div>
        <div class="sidebar-section">
            <div class="sidebar-title">Channels / Queries</div>
            <div id="channel-list">
                {% for chan in channels %}
                    {% set is_chan = chan.startswith('#') %}
                    {% set clean_name = chan.replace('#', '') %}
                    {% set link_url = url_for('channel_view', name=clean_name) if is_chan else url_for('query_view', name=clean_name) %}
                    <a href="{{ link_url }}" class="list-item {% if chan == true_target %}active{% endif %}">
                       {{ chan }}
                    </a>
                {% endfor %}
            </div>
        </div>
        <div class="sidebar-section">
            <div class="sidebar-title">Nicklist</div>
            <div id="nick-list">
                {% for nick in nicks %}
                    <div class="list-item nick-item" onclick="openQuery('{{ nick }}')">{{ nick }}</div>
                {% endfor %}
            </div>
        </div>
    </div>
</div>
<script>
    // |tojson on every value interpolated into JS: a channel name is
    // server-supplied and would otherwise be able to break out of the literal.
    const activeTarget = {{ true_target|tojson }};
    const channelUrlBase = {{ url_for('channel_view', name='PLACEHOLDER')|tojson }};
    const queryUrlBase = {{ url_for('query_view', name='PLACEHOLDER')|tojson }};
    const sendUrl = {{ url_for('send_message')|tojson }};
    const pollUrlBase = {{ url_for('poll_state', name='PLACEHOLDER')|tojson }};

    const chatBox = document.getElementById('chat-box');
    const msgInput = document.getElementById('msg-input');
    const sendBtn = document.getElementById('send-btn');
    const statusLine = document.getElementById('status-line');
    const nickList = document.getElementById('nick-list');
    const chanList = document.getElementById('channel-list');

    // Highest message id already on screen. Comparing ids rather than list
    // lengths keeps updates flowing once the server-side buffer rolls over.
    let lastSeq = {{ last_seq }};
    let lastNickSig = null;
    let lastChanSig = null;

    msgInput.focus();
    chatBox.scrollTop = chatBox.scrollHeight;

    function showStatus(text) { statusLine.textContent = text || ''; }

    function withCacheBust(url) {
        return url + (url.indexOf('?') === -1 ? '?' : '&') + '_=' + Date.now();
    }

    function openQuery(nick) {
        window.location.href = queryUrlBase.replace('PLACEHOLDER', encodeURIComponent(nick));
    }

    function appendMessage(msg) {
        const div = document.createElement('div');
        div.className = 'msg';
        // textContent for everything the client did not already escape; only
        // msg.html is pre-sanitized by parse_irc_message() on the server.
        const time = document.createElement('span');
        time.className = 'time';
        time.textContent = msg.time;
        const user = document.createElement('span');
        user.className = 'user';
        user.textContent = msg.user;
        const text = document.createElement('span');
        text.className = 'text';
        text.innerHTML = msg.html;
        div.append(time, user, text);
        chatBox.appendChild(div);
    }

    function rebuildNicks(nicks) {
        nickList.textContent = '';
        for (const nick of nicks) {
            const div = document.createElement('div');
            div.className = 'list-item nick-item';
            div.textContent = nick;
            div.addEventListener('click', () => openQuery(nick));
            nickList.appendChild(div);
        }
    }

    function rebuildChannels(channels) {
        chanList.textContent = '';
        for (const chan of channels) {
            const isChan = chan.charAt(0) === '#';
            const clean = isChan ? chan.slice(1) : chan;
            const link = document.createElement('a');
            link.className = 'list-item' + (chan === activeTarget ? ' active' : '');
            link.href = (isChan ? channelUrlBase : queryUrlBase)
                .replace('PLACEHOLDER', encodeURIComponent(clean));
            link.textContent = chan;
            chanList.appendChild(link);
        }
    }

    function sendMessage() {
        const text = msgInput.value;
        if (!text) return;
        showStatus('');
        sendBtn.disabled = true;
        const formData = new FormData();
        formData.append('target', activeTarget);
        formData.append('message', text);

        fetch(sendUrl, { method: 'POST', body: formData })
        .then(r => r.json().catch(() => ({ status: 'error', error: 'HTTP ' + r.status })))
        .then(data => {
            if (data.status === 'redirect') { window.location.href = data.url; return; }
            if (data.status === 'error') {
                showStatus(data.error || 'Send failed');
                msgInput.focus();
                return;
            }
            msgInput.value = '';
            msgInput.focus();
            pollState();
        })
        .catch(() => showStatus('Network error - message was NOT sent'))
        .finally(() => { sendBtn.disabled = false; });
    }

    msgInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    });

    function pollState() {
        const cleanName = activeTarget.charAt(0) === '#' ? activeTarget.slice(1) : activeTarget;
        const url = withCacheBust(pollUrlBase.replace('PLACEHOLDER', encodeURIComponent(cleanName)));

        fetch(url, { cache: "no-store" })
        .then(r => r.json())
        .then(data => {
            document.getElementById('topic-display').textContent = data.topic || '';

            const fresh = (data.messages || []).filter(m => m.seq > lastSeq);
            if (fresh.length) {
                // Only follow the tail if the reader is already at the bottom,
                // so scrolling back through history is not yanked away.
                const pinned = chatBox.scrollTop + chatBox.clientHeight >= chatBox.scrollHeight - 40;
                fresh.forEach(appendMessage);
                lastSeq = fresh[fresh.length - 1].seq;
                while (chatBox.children.length > 1200) chatBox.removeChild(chatBox.firstChild);
                if (pinned) chatBox.scrollTop = chatBox.scrollHeight;
            }

            // Signatures, not lengths: a rename or reorder keeps the count the
            // same, and this used to leave stale entries on screen.
            const nickSig = (data.nicks || []).join(' ');
            if (nickSig !== lastNickSig) { rebuildNicks(data.nicks || []); lastNickSig = nickSig; }

            const chanSig = (data.channels || []).join(' ');
            if (chanSig !== lastChanSig) { rebuildChannels(data.channels || []); lastChanSig = chanSig; }
        })
        .catch(() => {});
    }

    setInterval(pollState, 1500);
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=FLASK_PORT)
