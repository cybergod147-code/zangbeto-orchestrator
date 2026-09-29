"""Lightweight JSON-backed model registry for Zangbeto.
Hot-reloadable — no restart needed when the active model changes."""
import json, threading
from pathlib import Path
from datetime import datetime, timezone

REGISTRY_PATH = Path(__file__).parent.parent / "data" / "ai_models.json"
_lock = threading.RLock()


def _load():
    with _lock:
        if not REGISTRY_PATH.exists():
            return {"active_model_id": None, "models": []}
        with open(REGISTRY_PATH) as f:
            return json.load(f)


def _save(data):
    with _lock:
        with open(REGISTRY_PATH, "w") as f:
            json.dump(data, f, indent=2)


def list_models(only_enabled=False):
    data = _load()
    models = data.get("models", [])
    if only_enabled:
        models = [m for m in models if m.get("enabled", True)]
    return {"active_model_id": data.get("active_model_id"), "models": models}


def get_model(model_id):
    for m in _load().get("models", []):
        if m["id"] == model_id:
            return m
    return None


def get_active_model():
    data = _load()
    active_id = data.get("active_model_id")
    if active_id:
        m = get_model(active_id)
        if m and m.get("enabled", True):
            return m
    for m in data.get("models", []):
        if m.get("enabled", True):
            return m
    return None


def set_active(model_id):
    data = _load()
    target = None
    for m in data.get("models", []):
        if m["id"] == model_id:
            target = m
            break
    if not target:
        return None
    data["active_model_id"] = model_id
    _save(data)
    return target


def add_model(model: dict):
    data = _load()
    if any(m["id"] == model["id"] for m in data["models"]):
        return None
    model.setdefault("enabled", True)
    model.setdefault("is_default", False)
    model["created_at"] = datetime.now(timezone.utc).isoformat()
    data["models"].append(model)
    _save(data)
    return model


def update_model(model_id, patch: dict):
    data = _load()
    for i, m in enumerate(data["models"]):
        if m["id"] == model_id:
            m.update(patch)
            m["updated_at"] = datetime.now(timezone.utc).isoformat()
            data["models"][i] = m
            _save(data)
            return m
    return None


def delete_model(model_id):
    data = _load()
    before = len(data["models"])
    data["models"] = [m for m in data["models"] if m["id"] != model_id]
    if data.get("active_model_id") == model_id:
        data["active_model_id"] = data["models"][0]["id"] if data["models"] else None
    _save(data)
    return len(data["models"]) < before
