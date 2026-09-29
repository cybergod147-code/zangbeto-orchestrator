```markdown
# Zangbeto Orchestrator

A self-hosted AI security orchestration platform. Combines multi-provider AI co-pilots, live Kali terminal integration, automated browser controls, and tamper-evident audit logging — all secured behind HTTPS.

## Features

- **Multi-Provider AI:** Local Ollama + OpenAI + DeepSeek + OpenRouter.
- **Hot-Swap Model Registry:** Switch models via the UI without restarting the service.
- **Live Kali Terminal:** Shared `tmux` session allowing you to watch the AI type in real time.
- **Dual Browser Modes:** AI-controlled headless Playwright and human-controlled Chromium VNC.
- **Approval Gates:** Every dangerous action requires explicit user confirmation.
- **Tamper-Evident Audit Chain:** SHA256-chained action logging for full traceability.
- **Scope Gate:** Refuses targets not listed in `data/authorized_targets.json`.
- **AI Kill Switch:** Instantly blocks all AI-initiated actions.
- **Advanced Reporting:** PDF, HTML, Markdown, and JSON reports with CVE enrichment.

## Architecture

| Layer | Tech | Port |
|---|---|---|
| Reverse proxy + SSL | Nginx + Let's Encrypt | 80/443 |
| Frontend | Next.js 16 (systemd) | 3001 |
| Backend | FastAPI + Uvicorn (systemd) | 8001 |
| AI (local) | Ollama | 11434 |
| Terminal | Kali + ttyd + tmux (Docker) | 7681 |
| AI Browser | Playwright headless (Docker) | — |
| Human Browser | Chromium + VNC (Docker) | 7800 |

## Supported Environments

| Platform | Status | Notes |
|---|---|---|
| Ubuntu VPS 22.04+ | ✅ Primary | Production |
| Kali Linux | ✅ Works | Local dev |
| Windows + WSL2 | ✅ Works | Use WSL2, not cmd or PowerShell |
| macOS | ⚠️ Untested | Should work |

## Install on a Fresh VPS

### Step 1 — Prerequisites

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw python3 python3-venv python3-pip \
  nodejs npm nginx certbot python3-certbot-nginx ffmpeg build-essential
```

### Step 2 — Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker
```

### Step 3 — Ollama + Model

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
ollama pull llama3.1:8b
```

### Step 4 — Clone the Repository

```bash
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/cybergod147-code/zangbeto-orchestrator.git zangbeto
cd zangbeto
```

### Step 5 — Configure Secrets

```bash
cp backend/.env.example backend/.env
nano backend/.env
```

Fill in the following values:
- `DEEPSEEK_API_KEY` — https://platform.deepseek.com/api_keys
- `OPENAI_API_KEY` — https://platform.openai.com/api-keys
- `OPENROUTER_API_KEY` — https://openrouter.ai/keys

Leave any provider blank to disable it. `DEFAULT_AI_PROVIDER=local` works with zero cloud keys.

### Step 6 — Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
mkdir -p ../data/audit_logs ../data/reports ../data/screenshots ../data/browser_shots
```

### Step 7 — Frontend Setup

```bash
cd ../frontend
npm ci
npm run build
```

### Step 8 — Systemd Services

```bash
sudo cp infra/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zangbeto-backend zangbeto-frontend zangbeto-ttyd
```

### Step 9 — Nginx + SSL

Replace `yourdomain.com` with your actual domain.

```bash
sudo cp infra/nginx/*.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/zangbeto.conf          /etc/nginx/sites-enabled/
sudo ln -sf /etc/nginx/sites-available/zangbeto-terminal.conf /etc/nginx/sites-enabled/
sudo ln -sf /etc/nginx/sites-available/zangbeto-browser.conf  /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

sudo certbot --nginx -d zangbeto.yourdomain.com
sudo certbot --nginx -d terminal.zangbeto.yourdomain.com
sudo certbot --nginx -d browser.zangbeto.yourdomain.com
```

### Step 10 — Docker Containers

```bash
# Kali Terminal
docker run -d --name zangbeto-kali-terminal \
  --restart unless-stopped \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 127.0.0.1:7681:7681 \
  kalilinux/kali-rolling sleep infinity

docker exec zangbeto-kali-terminal bash -c \
  "apt update -qq && apt install -y -qq tmux curl wget ca-certificates"
docker exec zangbeto-kali-terminal bash -c \
  "wget -q -O /usr/local/bin/ttyd https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 && chmod +x /usr/local/bin/ttyd"

# AI Browser (Playwright)
docker run -d --name zangbeto-browser \
  --restart unless-stopped \
  mcr.microsoft.com/playwright:v1.48.0-jammy sleep infinity

# Human Browser (VNC)
docker run -d --name zangbeto-vnc-browser \
  --restart unless-stopped \
  -e PUID=1000 -e PGID=1000 -e TZ=UTC \
  -e CUSTOM_USER=guardian -e PASSWORD=CHANGE_ME_STRONG \
  -e CHROME_CLI=https://google.com \
  -p 127.0.0.1:7800:3000 \
  -v /opt/zangbeto/data/browser_profile:/config \
  --shm-size="2gb" \
  lscr.io/linuxserver/chromium:latest
```

### Step 11 — First Login

Open `https://zangbeto.yourdomain.com` — the first-run wizard will create your account.

## API Reference

All endpoints require `Authorization: Bearer <token>`.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/auth/login` | Login → JWT token |
| GET | `/api/models` | List all models |
| POST | `/api/models/active` | Set active model |
| POST | `/api/models` | Add a model |
| DELETE | `/api/models/:id` | Delete a model |
| POST | `/api/models/test` | Test a model |
| GET | `/api/models/openrouter/catalog` | Live OpenRouter list |
| POST | `/api/chat` | Chat with active model |
| POST | `/api/execute` | Run command in sandbox |
| POST | `/api/terminal/write` | AI types in live terminal |
| POST | `/api/browser/action` | AI controls browser |
| POST | `/api/ai/kill-switch` | Engage / release kill switch |
| GET | `/api/audit/verify` | Verify audit chain |

## Troubleshooting

**Terminal tab shows 502 Bad Gateway**
ttyd isn't running inside the container:

```bash
docker exec -d zangbeto-kali-terminal tmux new-session -d -s shared
docker exec -d zangbeto-kali-terminal ttyd -p 7681 -W --interface 0.0.0.0 tmux attach -t shared
```

**AI says "No model configured"**

```bash
curl -X POST https://zangbeto.yourdomain.com/api/models/active \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model_id":"local-llama31"}'
```

**OpenRouter model reports "unavailable for free"**
The free tier rotates. Get today's live list:

```bash
curl "https://zangbeto.yourdomain.com/api/models/openrouter/catalog?free_only=true" \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Security

- API keys live in `backend/.env` — never exposed to the browser.
- `.env` is git-ignored.
- Every AI action is hashed into the tamper-evident audit chain.
- Scope gate blocks unauthorized targets.
- Dangerous commands (`rm -rf /`, `mkfs`, `dd`, `shutdown`) are rejected.
- Kill switch halts all AI action instantly.

## Authorized Targets

```bash
cp data/authorized_targets.example.json data/authorized_targets.json
nano data/authorized_targets.json
```

## License

Copyright (c) 2026. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use of this software, via any medium, is strictly prohibited. This software is provided for private and personal use only.
```
