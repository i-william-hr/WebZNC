# webznc

A web front end for an IRC bouncer. It logs in to a bouncer as a configured
account, keeps that connection open, and gives you a browser UI to read scrollback
and send messages — so you can catch up on a channel without keeping a native
IRC client open.

The bouncer is [ZNC](https://znc.in). This app speaks IRC to it and relays over
HTTP to the browser.

## This is a fork

This repository is a fork of, and replaces,
[https://github.com/i-william-hr/WebZNC](https://github.com/i-william-hr/WebZNC).
That project is the original; this one is the maintained version running on this
host. The original is kept for reference but is no longer developed here.

## What changed from the original

- **No application-level authentication.** The original shipped its own
  HTTP Basic auth plus a session cookie and a `?auth=` URL-key system, with a
  session-signing key stored in `webznc_secret.key`. All of that is gone. This
  app assumes a reverse proxy in front of it performs an auth subrequest against
  a single sign-on service — nginx gates `/znc` with an auth_request against
  SSO — so the SSO cookie is the only credential the web UI has.
- **No credentials in source.** The original hardcoded the ZNC account name and
  password directly in `webznc.py`. Everything is now read from `.env`, which is
  mode 0600 and is never committed (see `.gitignore`). See `.env.example` for the
  template.
- **`irc` library bumped.** The original ran the Debian `python3-irc` package,
  upstream 0.0.8.5.3 from 2018, which is uninstallable from PyPI because its
  tarball metadata disagrees with its filename. This app pins `irc==20.5.0`, a
  deliberate jump forward. See `requirements.txt` for the full explanation.
- **Thread safety.** The original shared state across Flask and IRC threads with
  no locking. `STATE` is now guarded by an RLock, each message carries a
  monotonically increasing sequence number, and polling returns only messages
  newer than the last seen sequence.
- **Echo suppression.** Messages this app sends are tracked in a short deque and
  discarded on arrival, so a sent line is not echoed back as a received line.
- **New IRC handlers.** `on_quit`, `on_kick`, and `on_nick` were added alongside
  the existing join/part/topic/nick/reply handlers, so the nicklist and channel
  list stay accurate as people come and go.
- **Send-path errors.** `/api/send` now returns 503 when not connected and 502 on
  exception, instead of reporting `ok` while the send silently failed.
- **iOS zoom fix.** The message input and the sidebar channel input set
  `font-size: 16px`, so focusing them on iOS Safari no longer triggers the
  page's small auto-zoom.

## What it does

- Connects to the bouncer over TLS and authenticates as a configured account
- Requests playback so recent messages are available immediately after connect
- Polls the bouncer on an interval and serves new lines to the browser
- Sends messages and topic changes back over the same connection
- Reconnects on a fixed delay if the connection drops

## Stack

Python, Flask, and the `irc` library. No database. The UI is HTML and
JavaScript served inline by the app.

## Running it

    python3 -m venv venv
    ./venv/bin/pip install -r requirements.txt
    ./venv/bin/python webznc.py

## Configuration

All of it lives in `.env` — see `.env.example`. The essentials:

- `ZNC_HOST`, `ZNC_PORT`, `ZNC_SSL_ENABLED` — where the bouncer is
- `ZNC_USER`, `ZNC_NET`, `ZNC_PASS` — the bouncer account to log in as
- `IRC_NICK` — the nickname to use on the connection
- `FLASK_PORT` — where this app listens
- `WEBZNC_LOG_LEVEL` — log level (default `INFO`)
- `MAX_MESSAGE_BYTES`, `MAX_TOPIC_BYTES`, `MAX_MESSAGES` — input limits
- `WEBZNC_SSL_NO_VERIFY` — see below

## Things worth knowing

**There is no authentication in this app.** It assumes a reverse proxy in front
of it performs an auth subrequest against a single sign-on service, and that
nothing else can reach the listening port. Everything the UI can do — read your
scrollback, send messages as you — is available to anyone who gets past that
gate. Bind to loopback. If you expose this directly, you have handed your IRC
session to the internet.

**`ZNC_PASS` is a real credential for a real account.** Depending on how you
configure it, that account may be an administrator with the ability to add and
remove users and read server configuration. Treat the file holding it as
sensitive.

**Certificate verification is off by default**, because bouncers typically
present self-signed certificates. This is fine on loopback and wrong anywhere
else. To turn it on properly, replace the bouncer's certificate with one that
chains to a trusted root, then set `WEBZNC_SSL_NO_VERIFY=0`.

**The `irc` library version is worth a look.** This app historically ran a 2018
release via a distribution package. Every 8.x release of that library is
uninstallable from PyPI — the published tarballs carry version metadata that
disagrees with their filenames — so the pin here is 20.5.0, a large jump
forward. It is verified working, but it is a jump.

**It runs Flask's development server.** That is not a hardened WSGI server. It
is tolerable behind a reverse proxy on loopback; it is not what you want if this
becomes internet-facing. Swap in `waitress` or `gunicorn` when that happens.