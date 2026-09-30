```markdown
# Zangbeto Orchestrator

> **Self-Hosted AI Security Orchestration & Controlled Cybersecurity Sandbox**

Zangbeto Orchestrator is a self-hosted AI security orchestration platform designed for controlled security research, authorized penetration testing, cybersecurity education, and isolated AI experimentation.

It combines **multi-provider AI models, local Ollama inference, a live Kali Linux terminal, browser automation, human-controlled browser access, authorization controls, approval gates, AI emergency controls, and tamper-evident audit logging** into a single security-focused environment.

The platform is designed around one core principle:
> **AI should assist security operations without removing human control.**

---

## ⚠️ Security & Legal Notice

Zangbeto Orchestrator is intended for:
- Authorized penetration testing
- Cybersecurity research
- Security education and training
- CTF/laboratory environments
- Defensive security testing
- Vulnerability validation
- Isolated sandbox experimentation
- Systems where the operator has explicit authorization

**Do not use this software against systems, networks, accounts, websites, devices, or infrastructure that you do not own or have explicit permission to test.**

The presence of a security tool, browser automation capability, terminal, or AI model does not grant authorization to use it against third-party systems. You are responsible for complying with all applicable laws, contracts, organizational policies, and rules of engagement.

---

## ✨ Core Features

- **Multi-Provider AI:** Connect Ollama, OpenAI, DeepSeek, OpenRouter, and local/self-hosted models through a unified orchestration layer. Cloud API credentials remain on the backend and are never exposed to the frontend.
- **Hot-Swap Model Registry:** Add, remove, activate, and test models dynamically. Switch providers or query OpenRouter's live catalog without restarting the platform.
- **Live Kali Terminal:** Connect to an isolated Kali Linux environment containing a shared `tmux` session. Observe terminal activity, interact with the sandbox, and review terminal activity through the audit system.
- **Dual Browser Architecture:** 
  - **AI Browser:** Headless Playwright environment designed for controlled browser automation.
  - **Human Browser:** Chromium running inside a VNC-accessible container for direct human interaction.
- **Approval Gates:** Potentially dangerous operations require explicit user approval before execution, creating a human-in-the-loop security model.
- **Scope Gate:** Explicit authorization list (`data/authorized_targets.json`). Targets not explicitly authorized are rejected by the application before an action is executed.
- **AI Kill Switch:** Emergency control for stopping AI-initiated actions immediately if an agent behaves unexpectedly or a security boundary needs to be enforced.
- **Tamper-Evident Audit Chain:** Security-sensitive actions are recorded in an audit chain using SHA-256 hashing. If an earlier event is modified, subsequent hashes become inconsistent. Provides an audit verification endpoint for checking chain integrity.
- **Advanced Reporting:** Support for PDF, HTML, Markdown, and JSON reports with CVE enrichment.

---

## 🏗️ Architecture

| Layer               | Technology                   |     Port |
| ------------------- | ---------------------------- | -------: |
| Reverse Proxy / SSL | Nginx + Let's Encrypt        | 80 / 443 |
| Frontend            | Next.js 16                   |     3001 |
| Backend             | FastAPI + Uvicorn            |     8001 |
| Local AI            | Ollama                       |    11434 |
| Security Terminal   | Kali + ttyd + tmux           |     7681 |
| AI Browser          | Playwright                   | Internal |
| Human Browser       | Chromium + VNC               |     7800 |
| Database / State    | Application-managed          |        — |
| Audit Storage       | SHA-256 chained logs         |        — |
| Reports             | PDF / HTML / Markdown / JSON |        — |

### High-Level Architecture

```text
                         INTERNET
                            │
                            ▼
                   ┌─────────────────┐
                   │      NGINX      │
                   │ Reverse Proxy   │
                   │   HTTPS / TLS   │
                   └────────┬────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
      ┌───────────────┐           ┌───────────────┐
      │   Next.js     │           │    FastAPI    │
      │   Frontend    │◄─────────►│    Backend    │
      │    :3001      │           │     :8001     │
      └───────────────┘           └───────┬───────┘
                                          │
                  ┌───────────────────────┼────────────────────────┐
                  │                       │                        │
                  ▼                       ▼                        ▼
          ┌──────────────┐       ┌────────────────┐       ┌──────────────┐
          │    Ollama    │       │ Cloud AI APIs  │       │ Audit Engine │
          │    :11434    │       │ OpenAI/DeepSeek│       │ SHA-256      │
          └──────────────┘       │ /OpenRouter    │       └──────────────┘
                                 └────────────────┘
                                          │
                          ┌───────────────┴───────────────┐
                          │                               │
                          ▼                               ▼
                 ┌─────────────────┐             ┌─────────────────┐
                 │  Kali Sandbox   │             │ Browser Layer   │
                 │ tmux + ttyd     │             │ Playwright/VNC  │
                 │     :7681       │             │     :7800       │
                 └─────────────────┘             └─────────────────┘
```

---

## 📦 Project Structure

```text
zangbeto/
├── backend/
│   ├── app/
│   ├── requirements.txt
│   ├── .env.example
│   └── .env
├── frontend/
│   ├── app/
│   ├── components/
│   ├── public/
│   ├── package.json
│   └── next.config.*
├── data/
│   ├── authorized_targets.example.json
│   ├── authorized_targets.json
│   ├── audit_logs/
│   ├── reports/
│   ├── screenshots/
│   ├── browser_shots/
│   └── browser_profile/
├── infra/
│   ├── nginx/
│   └── systemd/
├── docker/
├── scripts/
├── README.md
└── LICENSE
```

---

## 💻 Supported Environments

| Platform         | Status          | Notes                                      |
| ---------------- | --------------- | ------------------------------------------ |
| Ubuntu 22.04+    | ✅ Primary       | Recommended VPS deployment                 |
| Ubuntu 24.04 LTS | ✅ Recommended   | Production deployment                      |
| Kali Linux       | ✅ Supported     | Local security research                    |
| Windows + WSL2   | ✅ Supported     | Recommended Windows method                 |
| macOS            | ⚠️ Experimental | Validate environment-specific dependencies |

---

## 🚀 Installation

### 1. Prerequisites

Start with a fresh Ubuntu VPS or supported Linux environment.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw python3 python3-venv python3-pip \
  nodejs npm nginx certbot python3-certbot-nginx ffmpeg build-essential jq
```

Verify the important dependencies:
```bash
python3 --version && node --version && npm --version && nginx -v && git --version && docker --version
```

### 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker
sudo docker --version
# Optional: allow the current user to execute Docker without sudo
sudo usermod -aG docker "$USER"
```
*(Log out and back in after running this command)*

### 3. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
ollama --version
ollama pull llama3.1:8b
ollama list
curl http://127.0.0.1:11434/api/tags
```

### 4. Clone the Repository

```bash
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/cybergod147-code/zangbeto-orchestrator.git zangbeto
cd /opt/zangbeto
ls -la
```

### 5. Configure Environment Variables

```bash
cp backend/.env.example backend/.env
nano backend/.env
```

Example configuration:
```env
DEFAULT_AI_PROVIDER=local
OLLAMA_BASE_URL=http://127.0.0.1:11434
DEEPSEEK_API_KEY=
OPENAI_API_KEY=
OPENROUTER_API_KEY=
JWT_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_SECRET
ENVIRONMENT=production
```

Generate a secure JWT secret:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```
Copy the generated value into `JWT_SECRET=`. **Never commit `backend/.env` to Git.**

### 6. Backend Installation

```bash
cd /opt/zangbeto/backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
mkdir -p ../data/audit_logs ../data/reports ../data/screenshots ../data/browser_shots ../data/browser_profile
```

### 7. Frontend Installation

```bash
cd /opt/zangbeto/frontend
npm ci
npm run build
```

### 8. Configure systemd

```bash
sudo cp /opt/zangbeto/infra/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zangbeto-backend zangbeto-frontend zangbeto-ttyd
sudo systemctl start zangbeto-backend zangbeto-frontend zangbeto-ttyd
sudo systemctl status zangbeto-backend zangbeto-frontend zangbeto-ttyd
```

### 9. Configure Nginx

```bash
sudo cp /opt/zangbeto/infra/nginx/*.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/zangbeto.conf /etc/nginx/sites-enabled/
sudo ln -sf /etc/nginx/sites-available/zangbeto-terminal.conf /etc/nginx/sites-enabled/
sudo ln -sf /etc/nginx/sites-available/zangbeto-browser.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 10. Configure HTTPS (Let's Encrypt)

Replace the example domains with your actual domains.
```bash
sudo certbot --nginx -d zangbeto.yourdomain.com
sudo certbot --nginx -d terminal.zangbeto.yourdomain.com
sudo certbot --nginx -d browser.zangbeto.yourdomain.com
sudo certbot renew --dry-run
```

### 11. Deploy the Kali Terminal

```bash
docker run -d --name zangbeto-kali-terminal \
  --restart unless-stopped \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 127.0.0.1:7681:7681 \
  kalilinux/kali-rolling sleep infinity

docker exec zangbeto-kali-terminal bash -c \
  "apt update -qq && apt install -y -qq tmux curl wget ca-certificates"

docker exec zangbeto-kali-terminal bash -c \
  "wget -q -O /usr/local/bin/ttyd https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 && chmod +x /usr/local/bin/ttyd"

docker exec -d zangbeto-kali-terminal tmux new-session -d -s shared
docker exec -d zangbeto-kali-terminal ttyd -p 7681 -W --interface 0.0.0.0 tmux attach -t shared
docker ps
```

### 12. Deploy the AI Browser

```bash
docker run -d --name zangbeto-browser \
  --restart unless-stopped \
  mcr.microsoft.com/playwright:v1.48.0-jammy sleep infinity
docker ps --filter name=zangbeto-browser
```

### 13. Deploy the Human Browser

```bash
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
*Replace `CHANGE_ME_STRONG` with a unique, strong password before production use.*

### 14. Configure Authorized Targets

```bash
cd /opt/zangbeto
cp data/authorized_targets.example.json data/authorized_targets.json
nano data/authorized_targets.json
```
Only place systems that you are explicitly authorized to test inside this file.

### 15. First Login

Open `https://zangbeto.yourdomain.com` — the first-run wizard creates your account. Verify Dashboard, Backend, Ollama, Active AI model, Terminal, Browser, Audit logging, Kill switch, and Authorized target configuration.

---

## 🔌 API Reference

All endpoints require `Authorization: Bearer <token>`.

### Authentication
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/auth/login` | Authenticate and obtain JWT |

### Models
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/models` | List configured models |
| POST | `/api/models` | Add a model |
| POST | `/api/models/active` | Set active model |
| DELETE | `/api/models/:id` | Remove a model |
| POST | `/api/models/test` | Test model connectivity |
| GET | `/api/models/openrouter/catalog` | Retrieve OpenRouter catalog |

### AI
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/chat` | Send a message to the active model |
| POST | `/api/ai/kill-switch` | Engage or release AI action controls |

### Terminal & Browser
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/execute` | Execute an approved sandbox command |
| POST | `/api/terminal/write` | Send approved input to the terminal |
| POST | `/api/browser/action` | Execute an approved browser action |

### Auditing
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/audit/verify` | Verify audit-chain integrity |

---

## 🩺 Troubleshooting

**Terminal returns `502 Bad Gateway`**
```bash
docker ps --filter name=zangbeto-kali-terminal
docker exec zangbeto-kali-terminal ps aux | grep ttyd
docker exec -d zangbeto-kali-terminal tmux new-session -d -s shared
docker exec -d zangbeto-kali-terminal ttyd -p 7681 -W --interface 0.0.0.0 tmux attach -t shared
docker exec zangbeto-kali-terminal ss -lntp
```

**AI says "No model configured"**
```bash
curl http://127.0.0.1:11434/api/tags
ollama list
curl -X POST https://zangbeto.yourdomain.com/api/models/active \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model_id":"local-llama31"}'
```

**OpenRouter Free Model Availability**
```bash
curl "https://zangbeto.yourdomain.com/api/models/openrouter/catalog?free_only=true" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Check Logs**
```bash
# Backend
sudo journalctl -u zangbeto-backend --no-pager -n 100
# Frontend
sudo journalctl -u zangbeto-frontend --no-pager -n 100
# Nginx
sudo nginx -t && sudo tail -n 100 /var/log/nginx/error.log
# Docker
docker logs --tail 100 zangbeto-kali-terminal
```

---

## 🔐 Security Architecture

Zangbeto should be deployed using defense-in-depth.

- **Application Layer:** Authentication, JWT-based API authorization, Provider credential isolation, Model registry controls, Approval gates, Scope validation, Kill switch, Audit logging.
- **Network Layer:** HTTPS, Reverse proxy, Localhost-only internal ports where possible, Firewall rules, Restricted administrative access.
- **Container Layer:** Separate security containers, Explicit capabilities, Persistent browser profile isolation, Restricted port exposure, Container restart policies.
- **Data Layer:** Protected environment variables, Audit logs, Reports, Screenshots, Browser profiles, Authorized-target configuration.

### Secrets Management
Never commit secrets to Git. Sensitive files include `backend/.env`, `data/authorized_targets.json`, browser credentials, JWT secrets, API keys, and private certificates.
```bash
git status
git check-ignore backend/.env
```
If `.env` is not ignored, add it to `.gitignore`:
```text
backend/.env
.env
*.key
*.pem
```

### Firewall (UFW)
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
sudo ufw enable
sudo ufw status verbose
```
**Do not expose internal application ports such as 8001, 7681, 7800, or 11434 directly to the public internet.**

### Recommended Production Hardening
- Use HTTPS everywhere
- Use strong administrator passwords
- Generate a cryptographically strong JWT secret
- Keep API keys server-side
- Restrict Ollama to trusted interfaces
- Keep internal ports private
- Configure UFW
- Keep Docker and host packages updated
- Keep application dependencies updated
- Review container privileges and Linux capabilities
- Restrict SSH access (disable password auth, use SSH keys)
- Configure backups, protect audit logs, monitor disk/CPU/memory
- Review authorization scope regularly
- Test the kill switch, audit verification, and recovery procedures

---

## 🔎 Monitoring & Maintenance

**Useful system commands:**
```bash
htop                  # CPU and memory
df -h                 # Disk
free -h               # Memory
docker stats          # Docker resource usage
docker ps             # Running containers
sudo ss -lntup        # Listening ports
systemctl --failed    # System services
```

**Backup Strategy:**
Recommended directories: `/opt/zangbeto/backend/.env` and `/opt/zangbeto/data/`
```bash
sudo tar -czf zangbeto-backup-$(date +%Y%m%d-%H%M%S).tar.gz /opt/zangbeto/data
```
Store backups outside the production server. Do not store production API keys in publicly accessible backup locations.

**Audit Verification:**
```bash
curl https://zangbeto.yourdomain.com/api/audit/verify -H "Authorization: Bearer $TOKEN"
```
Protect the underlying log storage using restricted filesystem permissions, separate backup storage, immutable/object-lock storage, external monitoring, and restricted administrator access.

---

## 🧠 Human-in-the-Loop Model

Zangbeto is designed so that AI does not automatically become the final authority over security operations. The intended control flow is:

```text
                 USER
                  │
                  ▼
             AI REQUEST
                  │
                  ▼
          POLICY VALIDATION
                  │
        ┌─────────┴─────────┐
        │                   │
     DENIED              APPROVED
        │                   │
        ▼                   ▼
      STOP             SCOPE CHECK
                            │
                   ┌────────┴────────┐
                   │                 │
                OUTSIDE            INSIDE
                   │                 │
                   ▼                 ▼
                 STOP          APPROVAL GATE
                                      │
                              ┌───────┴───────┐
                              │               │
                           DENIED          APPROVED
                              │               │
                              ▼               ▼
                            STOP           EXECUTE
                                              │
                                              ▼
                                        AUDIT EVENT
```
This architecture provides multiple opportunities to stop an operation before execution.

---

## 🚨 Emergency Procedure

If an AI-controlled operation behaves unexpectedly:
1. **Engage the AI Kill Switch** in the application emergency control.
2. **Stop the relevant container:**
   ```bash
   docker stop zangbeto-kali-terminal
   docker stop zangbeto-browser
   docker stop zangbeto-vnc-browser
   ```
3. **Stop AI services if necessary:**
   ```bash
   sudo systemctl stop zangbeto-backend
   ```
4. **Inspect logs:**
   ```bash
   sudo journalctl -u zangbeto-backend --no-pager -n 200
   ```
5. **Review the audit chain:** Verify `/api/audit/verify`.
6. **Re-establish the authorized scope** before restarting operations.

---

## 🔄 Updating Zangbeto

Back up important application data first. Then:
```bash
cd /opt/zangbeto
git pull
```
Backend:
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
deactivate
```
Frontend:
```bash
cd ../frontend
npm ci
npm run build
```
Reload services:
```bash
sudo systemctl daemon-reload
sudo systemctl restart zangbeto-backend zangbeto-frontend zangbeto-ttyd
sudo systemctl status zangbeto-backend zangbeto-frontend zangbeto-ttyd
```

---

## 📝 License

Copyright (c) 2026 Cyber God / Zangbeto Orchestrator. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, redistribution, resale, publication, sublicensing, reverse engineering, or commercial use is prohibited unless explicitly authorized by the copyright holder. The software is provided for authorized private, educational, research, and security-testing purposes subject to applicable law and the terms under which the software is distributed.

---

## 👤 Maintainer

**Cyber God**
Zangbeto Orchestrator

> **AI-assisted security research with human control at the center.**
```
