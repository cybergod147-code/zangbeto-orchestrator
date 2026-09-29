from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests, os, json, shutil, subprocess, re, hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from faster_whisper import WhisperModel

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except Exception:
    pass

import httpx

from auth import (setup_required, save_user, verify_password,
                  create_token, verify_token)
from screenshot_renderer import render_terminal_screenshot, count_by_severity
from cve_lookup import extract_services_from_nmap_output, enrich_services_with_cves
from report_builder import (build_pdf_report, build_markdown_report,
                            build_json_report, build_html_report)

# ── MODEL REGISTRY ────────────────────────────────────────────────
from model_registry import (
    list_models as reg_list_models,
    get_model as reg_get_model,
    get_active_model as reg_get_active,
    set_active as reg_set_active,
    add_model as reg_add_model,
    update_model as reg_update_model,
    delete_model as reg_delete_model,
)

app = FastAPI(title="Zangbeto API")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
AUDIT_DIR = DATA_DIR / "audit_logs"
REPORTS_DIR = DATA_DIR / "reports"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"
BROWSER_SHOTS_DIR = DATA_DIR / "browser_shots"
TARGETS_FILE = DATA_DIR / "authorized_targets.json"
for d in [AUDIT_DIR, REPORTS_DIR, SCREENSHOTS_DIR, BROWSER_SHOTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

print("Loading Whisper model...")
whisper_model = WhisperModel("base", device="cpu", compute_type="int8")
print("Whisper ready.")


# ═══════════════════════════════════════════════════════════════════
# AI KILL SWITCH
# ═══════════════════════════════════════════════════════════════════
AI_KILL_SWITCH = {"engaged": False, "changed_at": None, "changed_by": None}


# ═══════════════════════════════════════════════════════════════════
# SYSTEM PROMPTS
# ═══════════════════════════════════════════════════════════════════
SYSTEM_PROMPT_CHAT = """You are Zangbeto, a friendly, sharp AI assistant and cybersecurity co-pilot running on the Guardian's private VPS.

You help with:
- Security strategy, planning, and next-step suggestions
- Explaining and using Kali Linux tools (nmap, sqlmap, hydra, ffuf, nuclei, etc.)
- Writing code (Python, Bash, JavaScript, etc.)
- General questions, brainstorming, and casual conversation
- CTF tactics, red teaming, blue teaming, and defensive concepts

Behaviour rules:
1. Greetings and small talk get conversational replies. NEVER auto-generate a command for "hello", "how are you", "what's up", etc.
2. Only suggest or generate a shell command when the user asks for one or clearly needs to run something.
3. When you suggest a command, put it in a ```bash code block and explain in one short line what it does.
4. Be concise, friendly, and helpful. Emoji allowed occasionally.
5. Never refuse a legitimate question about security concepts or tools.
6. You cannot execute anything yourself — the Guardian decides where to run it. Never claim you scanned or found something.
7. For browser tasks, suggest ```browser navigate <url>```, ```browser screenshot```, ```browser click <selector>```, or ```browser fill <selector> <text>```.

Environment (the Guardian picks which to use — you only suggest):
- SANDBOX: disposable Kali container. Safe for quick scans and one-off tools.
- LIVE TERMINAL: persistent tmux session the Guardian can watch in real time.
- BROWSER: headless Chromium for web ops and screenshots.

Talk like a smart, friendly colleague — not a rigid robot."""

SYSTEM_PROMPT_ADVISOR = """You are Zangbeto, a senior cybersecurity orchestrator. Address the user as 'Guardian'.

For every task, respond in this exact structure:
1. One-line tactical objective
2. The command inside a ```bash block
3. One-line expected outcome

Rules:
- Never execute. Only suggest.
- Never pick the environment (sandbox vs live). The Guardian chooses.
- Be terse and tactical. No lectures.
- Greetings get conversational replies — do NOT force a command."""


# ═══════════════════════════════════════════════════════════════════
# CLOUD PROVIDERS
# ═══════════════════════════════════════════════════════════════════
PROVIDERS = {
    "local": {
        "label": "Local (Ollama)",
        "type": "ollama",
    },
    "deepseek": {
        "label": "DeepSeek (cloud)",
        "type": "openai-compat",
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
    },
    "openai": {
        "label": "OpenAI (cloud)",
        "type": "openai-compat",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "openrouter": {
        "label": "OpenRouter (cloud)",
        "type": "openai-compat",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "extra_headers": {
            "HTTP-Referer": "https://zangbeto.gamers-hub.site",
            "X-Title": "Zangbeto Orchestrator",
        },
    },
}


# ═══════════════════════════════════════════════════════════════════
# AI PROVIDER HELPERS
# ═══════════════════════════════════════════════════════════════════

def _provider_status() -> dict:
    """Report which providers have an API key configured."""
    status = {}
    for key, cfg in PROVIDERS.items():
        if cfg["type"] == "ollama":
            status[key] = {"label": cfg["label"], "available": True}
        else:
            has_key = bool(os.getenv(cfg["api_key_env"], "").strip())
            status[key] = {"label": cfg["label"], "available": has_key}
    return status


async def _ask_ollama(prompt: str, system: str, model_name: str) -> str:
    async with httpx.AsyncClient(timeout=300) as client:
        r = await client.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": model_name,
                "prompt": prompt,
                "system": system,
                "stream": False,
                "options": {"temperature": 0.7, "num_predict": 512},
            },
        )
        r.raise_for_status()
        return r.json().get("response", "") or ""


async def _ask_openai_compat(prompt: str, system: str, provider_key: str,
                              model_name: str) -> str:
    cfg = PROVIDERS[provider_key]
    api_key = os.getenv(cfg["api_key_env"], "").strip()
    if not api_key:
        raise HTTPException(status_code=400,
                            detail=f"{cfg['label']} API key not configured")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    headers.update(cfg.get("extra_headers", {}))

    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            f"{cfg['base_url']}/chat/completions",
            headers=headers,
            json={
                "model": model_name,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.7,
                "stream": False,
            },
        )
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code,
                                detail=f"{cfg['label']} error: {r.text[:400]}")
        data = r.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            return f"[{cfg['label']} returned unexpected response]"


async def _route_to_provider(prompt: str, system: str,
                              provider_key: str, model_name: str) -> str:
    """Send the prompt to the right provider with an explicit model name."""
    if provider_key not in PROVIDERS:
        raise HTTPException(status_code=400,
                            detail=f"Unknown provider: {provider_key}")
    cfg = PROVIDERS[provider_key]
    if cfg["type"] == "ollama":
        return await _ask_ollama(prompt, system, model_name)
    return await _ask_openai_compat(prompt, system, provider_key, model_name)


# ═══════════════════════════════════════════════════════════════════
# AUTH / AUDIT
# ═══════════════════════════════════════════════════════════════════

def require_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.replace("Bearer ", "")
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


def require_ai_enabled():
    if AI_KILL_SWITCH["engaged"]:
        raise HTTPException(status_code=423,
                            detail="AI kill switch engaged. Re-enable AI to proceed.")


def load_authorized_targets():
    try:
        with open(TARGETS_FILE) as f:
            data = json.load(f)
        return set(data.get("authorized_targets", [])) | set(data.get("authorized_domains", []))
    except Exception:
        return set()


def extract_targets_from_command(command: str) -> list:
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", command)
    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", command)
    excluded = {"nmap.org", "wireshark.org", "kali.org", "python.org"}
    domains = [d for d in domains if d not in excluded]
    return list(set(ips + domains))


def check_scope_gate(command: str):
    authorized = load_authorized_targets()
    extracted = extract_targets_from_command(command)
    if not extracted:
        return (True, [], [])
    unauthorized = [t for t in extracted if t not in authorized]
    return (not unauthorized, extracted, unauthorized)


def get_last_audit_hash() -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = AUDIT_DIR / f"audit_{today}.jsonl"
    if not log_file.exists():
        return "0" * 64
    try:
        with open(log_file) as f:
            lines = f.readlines()
        if not lines:
            return "0" * 64
        return json.loads(lines[-1]).get("hash", "0" * 64)
    except Exception:
        return "0" * 64


def write_audit_entry(action: str, actor: str, details: dict) -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = AUDIT_DIR / f"audit_{today}.jsonl"
    previous_hash = get_last_audit_hash()
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = {"timestamp": timestamp, "action": action, "actor": actor,
             "details": details, "previous_hash": previous_hash}
    entry_string = json.dumps(entry, sort_keys=True)
    entry["hash"] = hashlib.sha256(entry_string.encode()).hexdigest()
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def verify_audit_chain() -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = AUDIT_DIR / f"audit_{today}.jsonl"
    if not log_file.exists():
        return {"status": "ok", "entries": 0, "message": "No entries today"}
    try:
        with open(log_file) as f:
            lines = f.readlines()
        expected = "0" * 64
        for i, line in enumerate(lines):
            entry = json.loads(line)
            if entry.get("previous_hash") != expected:
                return {"status": "tampered", "entries": i + 1,
                        "message": f"Chain broken at entry {i + 1}"}
            expected = entry.get("hash")
        return {"status": "ok", "entries": len(lines), "message": "Chain verified"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ═══════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str
    mode: str = "chat"
    provider: str = "auto"       # backward compat
    model_id: str = ""           # explicit model override from UI


class ExecuteRequest(BaseModel):
    command: str
    authorization_confirmed: bool = False


class ReportRequest(BaseModel):
    engagement_name: str = "Security Assessment"
    client_name: str = "Guardian"
    scope_notes: str = ""
    format: str = "pdf"


class LoginRequest(BaseModel):
    username: str
    password: str


class SetupRequest(BaseModel):
    username: str
    password: str


class IdleLogoutRequest(BaseModel):
    username: str


class TerminalWriteRequest(BaseModel):
    command: str
    authorization_confirmed: bool = False


class SystemNotifyRequest(BaseModel):
    message: str
    color: str = "green"


class BrowserActionRequest(BaseModel):
    action: str
    arg1: str = ""
    arg2: str = ""
    authorization_confirmed: bool = False


class SandboxWriteRequest(BaseModel):
    command: str


class KillSwitchRequest(BaseModel):
    engage: bool


class SetActiveRequest(BaseModel):
    model_id: str


class AddModelRequest(BaseModel):
    id: str
    name: str
    provider: str
    model_id: str
    free: bool = True
    context_length: Optional[int] = None
    supports_tools: bool = False
    supports_vision: bool = False
    reasoning: bool = False
    description: str = ""
    enabled: bool = True


class UpdateModelRequest(BaseModel):
    enabled: Optional[bool] = None
    name: Optional[str] = None
    description: Optional[str] = None
    supports_tools: Optional[bool] = None
    supports_vision: Optional[bool] = None
    reasoning: Optional[bool] = None


class TestModelRequest(BaseModel):
    model_id: str


# ═══════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/auth/setup-required")
def auth_setup_required():
    return {"setup_required": setup_required()}


@app.post("/api/auth/setup")
def auth_setup(req: SetupRequest):
    if not setup_required():
        raise HTTPException(status_code=400, detail="Already set up")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    save_user(req.username, req.password)
    token = create_token(req.username)
    write_audit_entry("user_SETUP", req.username, {})
    return {"status": "success", "token": token, "username": req.username}


@app.post("/api/auth/login")
def auth_login(req: LoginRequest):
    if not verify_password(req.username, req.password):
        write_audit_entry("login_FAILED", req.username, {})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(req.username)
    write_audit_entry("login_SUCCESS", req.username, {})
    return {"status": "success", "token": token, "username": req.username}


@app.post("/api/audit/idle-logout")
def idle_logout(req: IdleLogoutRequest):
    write_audit_entry("session_IDLE_TIMEOUT", req.username, {})
    return {"status": "logged"}


@app.get("/")
def root():
    return {"status": "Zangbeto is watching."}


# ═══════════════════════════════════════════════════════════════════
# AI PROVIDERS + KILL SWITCH
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/ai/providers")
def ai_providers(user: dict = Depends(require_auth)):
    return {
        "providers": _provider_status(),
        "kill_switch": AI_KILL_SWITCH,
    }


@app.post("/api/ai/kill-switch")
def toggle_kill_switch(req: KillSwitchRequest, user: dict = Depends(require_auth)):
    AI_KILL_SWITCH["engaged"] = req.engage
    AI_KILL_SWITCH["changed_at"] = datetime.now(timezone.utc).isoformat()
    AI_KILL_SWITCH["changed_by"] = user["username"]
    write_audit_entry(
        "ai_kill_switch_ENGAGED" if req.engage else "ai_kill_switch_DISENGAGED",
        user["username"], {"engaged": req.engage})
    return {"status": "success", "kill_switch": AI_KILL_SWITCH}


@app.get("/api/ai/kill-switch")
def kill_switch_status(user: dict = Depends(require_auth)):
    return AI_KILL_SWITCH


# ═══════════════════════════════════════════════════════════════════
# MODEL REGISTRY ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/models")
def list_models_endpoint(user: dict = Depends(require_auth)):
    """List all models (enabled + disabled)."""
    return reg_list_models(only_enabled=False)


@app.get("/api/models/enabled")
def list_enabled_models_endpoint(user: dict = Depends(require_auth)):
    """List enabled models — for the chat UI dropdown."""
    return reg_list_models(only_enabled=True)


@app.post("/api/models/active")
def set_active_model(req: SetActiveRequest, user: dict = Depends(require_auth)):
    """Set the active model. No restart required."""
    m = reg_set_active(req.model_id)
    if not m:
        raise HTTPException(status_code=404, detail="Model not found")
    write_audit_entry("model_ACTIVATED", user["username"],
                      {"model_id": req.model_id, "name": m["name"]})
    return {"status": "success", "model": m}


@app.post("/api/models")
def add_model_endpoint(req: AddModelRequest, user: dict = Depends(require_auth)):
    m = reg_add_model(req.dict())
    if not m:
        raise HTTPException(status_code=409, detail="Model ID already exists")
    write_audit_entry("model_ADDED", user["username"], {"model": m})
    return {"status": "success", "model": m}


@app.patch("/api/models/{model_id}")
def update_model_endpoint(model_id: str, req: UpdateModelRequest,
                          user: dict = Depends(require_auth)):
    patch = {k: v for k, v in req.dict().items() if v is not None}
    m = reg_update_model(model_id, patch)
    if not m:
        raise HTTPException(status_code=404, detail="Model not found")
    write_audit_entry("model_UPDATED", user["username"],
                      {"model_id": model_id, "patch": patch})
    return {"status": "success", "model": m}


@app.delete("/api/models/{model_id}")
def delete_model_endpoint(model_id: str, user: dict = Depends(require_auth)):
    ok = reg_delete_model(model_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Model not found")
    write_audit_entry("model_DELETED", user["username"], {"model_id": model_id})
    return {"status": "success"}


@app.post("/api/models/test")
async def test_model_endpoint(req: TestModelRequest, user: dict = Depends(require_auth)):
    """Send a tiny test request to verify a model works."""
    m = reg_get_model(req.model_id)
    if not m:
        raise HTTPException(status_code=404, detail="Model not found")

    provider_key = m["provider"]
    model_name = m["model_id"]
    started = datetime.now(timezone.utc)

    try:
        reply = await _route_to_provider(
            "Say the single word: ok",
            "You are a test responder. Reply with exactly: ok",
            provider_key, model_name)
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        write_audit_entry("model_TEST_OK", user["username"],
                          {"model_id": req.model_id, "latency_ms": elapsed_ms})
        return {"status": "ok", "latency_ms": elapsed_ms,
                "reply_preview": reply[:120],
                "provider": provider_key, "model": model_name}
    except HTTPException as e:
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        write_audit_entry("model_TEST_FAIL", user["username"],
                          {"model_id": req.model_id, "error": e.detail})
        return {"status": "error", "latency_ms": elapsed_ms,
                "error": e.detail, "provider": provider_key, "model": model_name}
    except Exception as e:
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        write_audit_entry("model_TEST_FAIL", user["username"],
                          {"model_id": req.model_id, "error": str(e)})
        return {"status": "error", "latency_ms": elapsed_ms,
                "error": str(e), "provider": provider_key, "model": model_name}


# ═══════════════════════════════════════════════════════════════════
# OPENROUTER CATALOG DISCOVERY
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/models/openrouter/catalog")
async def openrouter_catalog(free_only: bool = False, search: str = "",
                              user: dict = Depends(require_auth)):
    """Fetch the live OpenRouter model catalog (server-side, key never exposed)."""
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=400,
                            detail="OpenRouter API key not configured")

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"})
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        raise HTTPException(status_code=502,
                            detail=f"Failed to fetch OpenRouter catalog: {e}")

    out = []
    for m in data.get("data", []):
        pricing = m.get("pricing", {}) or {}
        try:
            p_in = float(pricing.get("prompt", "0") or 0)
            p_out = float(pricing.get("completion", "0") or 0)
        except (ValueError, TypeError):
            p_in = p_out = 0.0
        is_free = (p_in == 0 and p_out == 0)

        if free_only and not is_free:
            continue
        if search and search.lower() not in (
            m.get("id", "") + " " + m.get("name", "")
        ).lower():
            continue

        arch = m.get("architecture", {}) or {}
        out.append({
            "id": m.get("id"),
            "name": m.get("name", m.get("id")),
            "context_length": m.get("context_length"),
            "pricing": {"prompt": p_in, "completion": p_out},
            "free": is_free,
            "description": m.get("description", "")[:300],
            "input_modalities": arch.get("input_modalities", []),
            "output_modalities": arch.get("output_modalities", []),
            "supports_tools": "tools" in (m.get("supported_parameters") or []),
        })

    out.sort(key=lambda x: (not x["free"], x["name"] or ""))
    return {"count": len(out), "models": out[:200]}


# ═══════════════════════════════════════════════════════════════════
# SANDBOX TERMINAL
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/sandbox/write")
def sandbox_write(req: SandboxWriteRequest, user: dict = Depends(require_auth)):
    if not req.command.strip():
        return {"status": "error", "output": ""}
    try:
        result = subprocess.run(
            ["docker", "exec", "zangbeto-sandbox", "sh", "-c", req.command],
            capture_output=True, text=True, timeout=60)
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        if not output.strip():
            output = "[Command completed with no output]"
        write_audit_entry("sandbox_user_command", user["username"],
                          {"command": req.command})
        return {"status": "success", "output": output}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": "⏱️ Command timed out after 60s."}
    except Exception as e:
        return {"status": "error", "output": f"Sandbox error: {str(e)}"}


# ═══════════════════════════════════════════════════════════════════
# SHARED TERMINAL
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/terminal/read")
def terminal_read(user: dict = Depends(require_auth)):
    try:
        result = subprocess.run(
            ["docker", "exec", "zangbeto-kali-terminal",
             "tmux", "capture-pane", "-t", "shared", "-p", "-S", "-100"],
            capture_output=True, text=True, timeout=10)
        return {"status": "success", "output": result.stdout}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/terminal/write")
def terminal_write(req: TerminalWriteRequest, user: dict = Depends(require_auth),
                   _: None = Depends(require_ai_enabled)):
    if not req.authorization_confirmed:
        write_audit_entry("terminal_write_REQUIRED", user["username"],
                          {"command": req.command})
        return {"status": "authorization_required",
                "message": "User must confirm this action"}

    dangerous = ["rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
                 "> /dev/sda", "shutdown", "reboot", "passwd", "useradd",
                 "deluser", "chmod -R 777 /", ":(){ :|:& };:"]
    for p in dangerous:
        if p in req.command:
            write_audit_entry("terminal_write_BLOCKED", user["username"],
                              {"command": req.command, "pattern": p})
            return {"status": "blocked", "message": f"Blocked: {p}"}

    try:
        subprocess.run(
            ["docker", "exec", "zangbeto-kali-terminal",
             "tmux", "send-keys", "-t", "shared", req.command, "Enter"],
            capture_output=True, text=True, timeout=10)
        write_audit_entry("terminal_write_EXECUTED", user["username"],
                          {"command": req.command})
        return {"status": "success", "message": f"Sent to terminal: {req.command}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/terminal/system-notify")
def system_notify(req: SystemNotifyRequest, user: dict = Depends(require_auth)):
    try:
        safe_msg = req.message.replace("'", "")
        color_code = "\\033[1;31m" if req.color == "red" else "\\033[1;32m"
        subprocess.run(
            ["docker", "exec", "zangbeto-kali-terminal",
             "tmux", "send-keys", "-t", "shared",
             f"echo -e '{color_code}[ZANGBETO] {safe_msg}\\033[0m'", "Enter"],
            capture_output=True, text=True, timeout=10)
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════
# AI BROWSER CONTROL
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/browser/action")
def browser_action(req: BrowserActionRequest, user: dict = Depends(require_auth),
                   _: None = Depends(require_ai_enabled)):
    if not req.authorization_confirmed:
        return {"status": "authorization_required",
                "message": "User must confirm browser action"}
    try:
        cmd = ["docker", "exec", "zangbeto-browser", "node",
               "/opt/security/browser-agent.js", req.action]
        if req.arg1: cmd.append(req.arg1)
        if req.arg2: cmd.append(req.arg2)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr

        screenshot_info = None
        if "SCREENSHOT:" in output:
            for line in output.split("\n"):
                if line.startswith("SCREENSHOT:"):
                    container_path = line.replace("SCREENSHOT:", "").strip()
                    filename = os.path.basename(container_path)
                    host_path = BROWSER_SHOTS_DIR / filename
                    subprocess.run(["docker", "cp",
                                    f"zangbeto-browser:{container_path}",
                                    str(host_path)],
                                   capture_output=True, text=True, timeout=30)
                    screenshot_info = filename
                    output = output.replace(line, f"[Screenshot saved: {filename}]")

        write_audit_entry("browser_action", user["username"],
                          {"action": req.action, "output": output[:500]})
        return {"status": "success", "output": output, "screenshot": screenshot_info}
    except Exception as e:
        return {"status": "error", "output": f"Browser error: {str(e)}"}


@app.get("/api/scope/targets")
def scope_targets(user: dict = Depends(require_auth)):
    a = load_authorized_targets()
    return {"authorized_targets": sorted(a), "count": len(a)}


@app.get("/api/audit/verify")
def audit_verify(user: dict = Depends(require_auth)):
    return verify_audit_chain()


@app.post("/api/transcribe")
async def transcribe(file: UploadFile = File(...), user: dict = Depends(require_auth)):
    tmp = f"temp_{file.filename}"
    with open(tmp, "wb") as b:
        shutil.copyfileobj(file.file, b)
    try:
        segments, _ = whisper_model.transcribe(tmp, beam_size=5)
        text = " ".join(s.text for s in segments)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return {"text": text.strip()}


# ═══════════════════════════════════════════════════════════════════
# CHAT (uses model registry)
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/chat")
async def chat(req: ChatRequest, user: dict = Depends(require_auth),
               _: None = Depends(require_ai_enabled)):
    # Resolve the model
    if req.model_id:
        model = reg_get_model(req.model_id)
        if not model or not model.get("enabled", True):
            raise HTTPException(status_code=400,
                                detail=f"Model '{req.model_id}' not available")
    else:
        model = reg_get_active()
        if not model:
            raise HTTPException(status_code=500,
                                detail="No AI model configured")

    provider_key = model["provider"]
    model_name = model["model_id"]

    write_audit_entry("chat_message", user["username"],
                      {"message": req.message, "mode": req.mode,
                       "provider": provider_key, "model_id": model_name})

    system = SYSTEM_PROMPT_ADVISOR if req.mode == "advisor" else SYSTEM_PROMPT_CHAT

    try:
        reply = await _route_to_provider(req.message, system,
                                          provider_key, model_name)
    except HTTPException as e:
        reply = f"⚠️ {e.detail}"
    except Exception as e:
        reply = f"Error: {type(e).__name__} — {e}"

    return {
        "status": "success",
        "reply": reply,
        "provider": provider_key,
        "model_id": model_name,
        "model_name": model["name"],
        "mode": req.mode,
    }


# ═══════════════════════════════════════════════════════════════════
# EXECUTE (approval-gated)
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/execute")
def execute(req: ExecuteRequest, user: dict = Depends(require_auth),
            _: None = Depends(require_ai_enabled)):
    raw = req.command.strip()
    command = re.sub(r"^```(?:bash|sh)?\s*", "", raw)
    command = re.sub(r"\s*```$", "", command).strip()

    is_auth, targets, unauthorized = check_scope_gate(command)
    if not is_auth:
        write_audit_entry("scope_gate_BLOCKED", user["username"],
                          {"command": command, "unauthorized": unauthorized})
        return {"status": "blocked", "reason": "SCOPE_GATE_VIOLATION",
                "output": (f"🛑 SCOPE GATE BLOCKED\n\n"
                           f"Unauthorized targets:\n  {', '.join(unauthorized)}\n\n"
                           f"Add them to:\n  {TARGETS_FILE}"),
                "unauthorized_targets": unauthorized}

    if not req.authorization_confirmed:
        write_audit_entry("authorization_REQUIRED", user["username"],
                          {"command": command, "targets": targets})
        return {"status": "authorization_required",
                "reason": "USER_CONFIRMATION_NEEDED",
                "output": (f"⚠️ AUTHORIZATION REQUIRED\n\n"
                           f"Command: {command}\n"
                           f"Targets: {', '.join(targets) if targets else 'none'}\n\n"
                           f"Confirm you have authorization."),
                "targets": targets}

    dangerous = ["rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
                 "> /dev/sda", "shutdown", "reboot"]
    for p in dangerous:
        if p in command:
            write_audit_entry("destructive_BLOCKED", user["username"],
                              {"command": command, "pattern": p})
            return {"status": "blocked", "reason": "DESTRUCTIVE_COMMAND",
                    "output": f"🛑 Destructive command blocked: {p}"}

    write_audit_entry("execute_START", user["username"],
                      {"command": command, "targets": targets})

    bugbounty_tools = ["nuclei", "subfinder", "httpx", "katana", "dnsx",
                       "naabu", "dalfox", "waybackurls", "assetfinder",
                       "httprobe", "gau", "gobuster", "wpscan", "testssl",
                       "amass", "ffuf"]
    first_word = command.strip().split()[0] if command.strip() else ""
    if first_word in bugbounty_tools:
        container = "zangbeto-bugbounty"
    elif "browser-visit" in command:
        container = "zangbeto-browser"
    else:
        container = "zangbeto-sandbox"

    if "browser-visit" in command:
        url_match = re.search(r"(https?://[^\s]+)", command)
        if not url_match:
            return {"status": "error",
                    "output": "No URL found. Usage: browser-visit https://example.com"}
        url = url_match.group(1)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        container_shot = f"/opt/security/browser_shots/shot_{ts}.png"
        host_shot = BROWSER_SHOTS_DIR / f"shot_{ts}.png"
        try:
            result = subprocess.run(
                ["docker", "exec", "zangbeto-browser", "node",
                 "/opt/security/browser-visit.js", url, container_shot],
                capture_output=True, text=True, timeout=60)
            output = result.stdout + ("\n" + result.stderr if result.stderr else "")
            cp = subprocess.run(
                ["docker", "cp", f"zangbeto-browser:{container_shot}",
                 str(host_shot)],
                capture_output=True, text=True, timeout=30)
            if cp.returncode == 0:
                output += f"\n[Screenshot saved: {host_shot.name}]"
            write_audit_entry("browser_visit", user["username"],
                              {"url": url, "screenshot": host_shot.name})
            return {"status": "success", "output": output,
                    "screenshot": host_shot.name if host_shot.exists() else None}
        except subprocess.TimeoutExpired:
            return {"status": "error", "output": "⏱️ Browser visit timed out after 60s."}
        except Exception as e:
            return {"status": "error", "output": f"Browser error: {str(e)}"}

    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
             container, "sh", "-c", command],
            capture_output=True, text=True, timeout=180)
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        if not output.strip():
            output = "[Command completed with no output]"

        screenshot_info = None
        important_tools = ["nmap", "masscan", "nikto", "sqlmap", "hydra",
                           "nuclei", "subfinder", "httpx", "dalfox",
                           "wpscan", "testssl"]
        if any(command.strip().startswith(t) or f" {t} " in command
               for t in important_tools):
            try:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                shot_path = SCREENSHOTS_DIR / f"findings_{ts}.png"
                render_terminal_screenshot(command, output, shot_path,
                                          target=targets[0] if targets else "local")
                screenshot_info = str(shot_path.name)
                severity = count_by_severity(output)
                write_audit_entry("screenshot_GENERATED", user["username"],
                                  {"screenshot": str(shot_path),
                                   "severity": severity})
            except Exception as e:
                print(f"Screenshot error: {e}")

        write_audit_entry("execute_COMPLETE", user["username"],
                          {"command": command, "container": container,
                           "exit_code": result.returncode,
                           "output_preview": output[:2000],
                           "screenshot": screenshot_info})

        return {"status": "success", "output": output,
                "screenshot": screenshot_info, "container": container}

    except subprocess.TimeoutExpired:
        write_audit_entry("execute_TIMEOUT", user["username"],
                          {"command": command})
        return {"status": "error", "output": "⏱️ Command timed out after 180s."}
    except Exception as e:
        write_audit_entry("execute_ERROR", user["username"],
                          {"command": command, "error": str(e)})
        return {"status": "error", "output": f"Execution error: {str(e)}"}


# ═══════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/report/generate")
def generate_report(req: ReportRequest, user: dict = Depends(require_auth)):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = AUDIT_DIR / f"audit_{today}.jsonl"
    entries = []
    if log_file.exists():
        with open(log_file) as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass

    executions = [e for e in entries
                  if e.get("action", "").startswith("execute_")
                  or e.get("action") == "scope_gate_BLOCKED"]

    all_services = []
    for e in entries:
        if e.get("action") == "execute_COMPLETE":
            cmd = e.get("details", {}).get("command", "")
            output = e.get("details", {}).get("output_preview", "")
            if "nmap" in cmd.lower():
                all_services.extend(extract_services_from_nmap_output(output))

    seen = set()
    unique_services = []
    for s in all_services:
        key = f"{s['port']}-{s['service']}"
        if key not in seen:
            seen.add(key)
            unique_services.append(s)
    enriched = enrich_services_with_cves(unique_services)

    screenshots = sorted(SCREENSHOTS_DIR.glob("findings_*.png"), reverse=True)[:10]
    audit_ver = verify_audit_chain()
    targets = load_authorized_targets()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fmt = req.format.lower()

    if fmt == "pdf":
        filename = f"report_{ts}.pdf"
        filepath = REPORTS_DIR / filename
        build_pdf_report(filepath, req.dict(), executions, screenshots,
                         enriched, audit_ver, targets)
    elif fmt == "md":
        filename = f"report_{ts}.md"
        filepath = REPORTS_DIR / filename
        build_markdown_report(filepath, req.dict(), executions, enriched,
                              audit_ver, targets)
    elif fmt == "json":
        filename = f"report_{ts}.json"
        filepath = REPORTS_DIR / filename
        build_json_report(filepath, req.dict(), executions, enriched,
                          audit_ver, targets)
    elif fmt == "html":
        filename = f"report_{ts}.html"
        filepath = REPORTS_DIR / filename
        build_html_report(filepath, req.dict(), executions, enriched,
                          audit_ver, targets)
    else:
        return {"status": "error", "message": f"Unsupported format: {fmt}"}

    write_audit_entry("report_GENERATED", user["username"],
                      {"filename": filename, "format": fmt,
                       "executions": len(executions)})

    return {"status": "success", "filename": filename, "path": str(filepath),
            "download_url": f"/api/report/download/{filename}",
            "total_executions": len(executions),
            "findings_count": len(enriched),
            "screenshots_count": len(screenshots)}


@app.get("/api/report/download/{filename}")
def download_report(filename: str, user: dict = Depends(require_auth)):
    filepath = REPORTS_DIR / filename
    if not filepath.exists():
        return {"status": "error", "message": "Report not found"}
    media_types = {".pdf": "application/pdf", ".md": "text/markdown",
                   ".json": "application/json", ".html": "text/html"}
    media = media_types.get(filepath.suffix, "application/octet-stream")
    return FileResponse(str(filepath), media_type=media, filename=filename)


@app.get("/api/report/list")
def list_reports(user: dict = Depends(require_auth)):
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.*"), reverse=True):
        if f.suffix in [".pdf", ".md", ".json", ".html"]:
            reports.append({
                "filename": f.name,
                "size_kb": round(f.stat().st_size / 1024, 1),
                "created": datetime.fromtimestamp(
                    f.stat().st_mtime, timezone.utc).isoformat(),
            })
    return {"reports": reports, "count": len(reports)}


# ═══════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════

def check_container_state(name: str) -> dict:
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Status}}|{{.State.StartedAt}}", name],
            capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return {"name": name, "status": "not_found", "running": False}
        parts = result.stdout.strip().split("|")
        status_str = parts[0] if parts else "unknown"
        started = parts[1] if len(parts) > 1 else ""
        return {"name": name, "status": status_str,
                "started_at": started, "running": status_str == "running"}
    except Exception as e:
        return {"name": name, "status": "error", "running": False, "error": str(e)}


def check_image(name: str) -> dict:
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Size}}", name],
            capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return {"name": name, "present": False}
        size_bytes = int(result.stdout.strip() or "0")
        return {"name": name, "present": True,
                "size_gb": round(size_bytes / (1024 ** 3), 2)}
    except Exception:
        return {"name": name, "present": False}


@app.get("/api/health")
def health(user: dict = Depends(require_auth)):
    containers = ["zangbeto-kali-terminal", "zangbeto-browser", "zangbeto-sandbox"]
    images = ["zangbeto-sandbox:latest", "zangbeto-bugbounty:latest"]
    container_status = [check_container_state(c) for c in containers]
    image_status = [check_image(i) for i in images]

    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        ollama_ok = r.status_code == 200
    except Exception:
        ollama_ok = False

    all_running = all(c["running"] for c in container_status) and ollama_ok

    return {
        "overall": "healthy" if all_running else "degraded",
        "containers": container_status,
        "images": image_status,
        "ollama": {"running": ollama_ok, "endpoint": "localhost:11434"},
        "backend": {"running": True, "version": "1.0"},
        "kill_switch": AI_KILL_SWITCH,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/health/restart/{container_name}")
def restart_container(container_name: str, user: dict = Depends(require_auth)):
    allowed = ["zangbeto-kali-terminal", "zangbeto-browser", "zangbeto-sandbox"]
    if container_name not in allowed:
        raise HTTPException(status_code=400, detail="Container not allowed")
    try:
        result = subprocess.run(["docker", "restart", container_name],
                                capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            write_audit_entry("container_RESTARTED", user["username"],
                              {"container": container_name})
            return {"status": "success", "message": f"{container_name} restarted"}
        return {"status": "error", "message": result.stderr}
    except Exception as e:
        return {"status": "error", "message": str(e)}
