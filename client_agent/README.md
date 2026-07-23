# Client-owned agent

The Telegram Mini App downloads `target-monitor-agent.json` directly onto the client device. It contains that client’s platform credentials and relay credential, so keep it private.

Copy `agent.py` and the JSON config to the client’s own always-on machine, then run:

```bash
python3 -m venv .venv
.venv/bin/pip install aiohttp beautifulsoup4
chmod 600 target-monitor-agent.json
.venv/bin/python agent.py --config target-monitor-agent.json
```

The agent calls platform scope endpoints directly using the client’s credential. It never sends the API identifier or API token to the relay. The only outgoing relay payloads are a whitelisted program summary and a signed new-target event destined for the same Telegram chat.

The first successful scan creates a local baseline. Notifications begin from the next added target. Keep the agent process running with systemd, Docker, Supervisor, or a similar user-owned process manager.
