# Private Target Monitor

Telegram-first bug-bounty target monitoring with a client-owned credential model.

The owner console is local-only. Each client opens `/web` in the Telegram bot, saves their own HackerOne connection in Telegram **SecureStorage**, and runs a small agent on their own PC/VPS/Raspberry Pi. That agent polls using the client’s own API token and sends only a signed new-target event to the relay. The relay has no API-key field, database column, or log path.

## Important architecture boundary

```
Telegram Mini App (client device)
  └─ SecureStorage: API identifier + token + local connections
       └─ downloaded private config
            └─ client-owned 24/7 agent
                 ├─ HackerOne/API source (token sent only here)
                 └─ relay: signed change + safe program summary only
                      └─ shared Telegram bot → same client's chat
```

- The shared server never receives a client platform API key.
- The relay stores a hashed agent relay credential, Telegram chat ID, and event IDs for de-duplication — not source URLs or API keys.
- `/program GitLab` displays only the safe summary that the client’s own agent synced for that client’s chat: active scope count/types, and bounty/resolved-report fields if the authorized source provides them.
- The first local agent scan is a baseline; it sends no old-target spam. A target found in later scans is sent to Telegram immediately after detection.

## Mini App versus 24/7 notifications

Telegram’s SecureStorage encrypts sensitive items at rest with device Keychain/Keystore, and is the correct place for Mini App secrets. See [Telegram Mini Apps — SecureStorage](https://core.telegram.org/bots/webapps).

However, a Mini App stops executing after it closes. It cannot poll a platform or deliver a future notification by itself. The supplied `client_agent/agent.py` must run on a client-owned always-on machine for 24/7 monitoring.

A Mini App URL must also be reachable over public HTTPS for Telegram clients to open it. Therefore this project exposes **only** `/miniapp/` and `/relay/` publicly. The owner dashboard, `/api/*`, SQLite database, and local owner API-key configuration stay on the local network.

## Owner setup

```bash
cd h1-target-monitor
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/bootstrap.py
```

Edit the resulting `.env`:

```dotenv
TELEGRAM_BOT_TOKEN=123456:replace-with-the-BotFather-token
MINI_APP_URL=https://monitor.example.com/miniapp/
RELAY_PUBLIC_URL=https://monitor.example.com/relay
LOCAL_WEB_ONLY=true
```

Run locally for the owner console:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` only from the owner’s local network. Docker does the same binding by default:

```bash
docker compose up --build -d
```

### Public reverse proxy allowlist

Put a TLS reverse proxy in front of the app and allow only the Mini App and relay paths. Do **not** publish the owner console or `/api`.

```nginx
server {
    listen 443 ssl;
    server_name monitor.example.com;

    location /miniapp/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /relay/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / { return 403; }
}
```

The compose port maps to `127.0.0.1`, so it cannot accidentally be reached directly from the internet. The application also rejects non-private addresses for owner-console routes when `LOCAL_WEB_ONLY=true`.

## Client setup

1. Client opens a private chat with the bot and sends `/start`, then `/web`.
2. Client taps **Allow & continue**. The Mini App uses Telegram SecureStorage, not ordinary localStorage.
3. Client adds an allowed HackerOne JSON scope feed, optional program-details JSON feed, and personal API token. The Mini App has no endpoint that accepts these fields. The details feed can expose resolved-report and bounty metrics for `/program`.
4. Client downloads `target-monitor-agent.json` directly to their device.
5. Client copies `client_agent/agent.py` and their downloaded JSON file to their own PC/VPS/Raspberry Pi, then runs:

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install aiohttp beautifulsoup4
   chmod 600 target-monitor-agent.json
   .venv/bin/python agent.py --config target-monitor-agent.json
   ```

6. Client keeps the agent running with systemd, Docker, Supervisor, or an equivalent local process manager.

The agent accepts an HTTPS JSON source containing `asset_identifier` (including JSON:API `attributes.asset_identifier`) or a program page whose returned HTML contains explicitly marked assets or a server-rendered scope table. It uses HackerOne API Basic authentication when an identifier/token pair is present. The configured token goes only from the client agent to that platform source.

## Telegram commands

- `/web` — one-time private Mini App setup link.
- `/program GitLab` — shows the caller’s locally synced program summary.
- `/program` — lists the caller’s synced programs.
- `/help` — security and agent reminder.

The bot cannot show another client’s program data because summaries are partitioned by the Telegram chat that created the relay credential.

## Security notes

- A shared bot token is kept solely on the owner server; never give it to client agents.
- The one-time `/web` link is short-lived, hash-stored, and contains no platform credential.
- The relay rejects unexpected JSON fields. It accepts only a whitelist of event/program-summary fields, so no code path is designed to receive an API token.
- Telegram SecureStorage protects secrets at rest, but a remotely served Mini App’s own JavaScript can read its own storage. For the strongest trust model, deploy the reviewed static Mini App bundle immutably and keep the long-running credential use inside the client-owned agent. Never run an unreviewed Mini App with a privileged platform token.
- Client agents should add only programs and scopes they are authorized to access, and must not redistribute private scope data.
