"""Password-based authentication with JWT sessions."""
import bcrypt
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from jose import jwt, JWTError

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
AUTH_FILE = DATA_DIR / "auth.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = "ZANGBETO_CHANGE_ME_BEFORE_VPS_DEPLOYMENT_xyz123"
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24


def load_user():
    if not AUTH_FILE.exists():
        return None
    try:
        with open(AUTH_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_user(username: str, password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with open(AUTH_FILE, "w") as f:
        json.dump({"username": username, "password_hash": hashed}, f)


def verify_password(username: str, password: str) -> bool:
    user = load_user()
    if not user or user.get("username") != username:
        return False
    try:
        return bcrypt.checkpw(password.encode(), user["password_hash"].encode())
    except Exception:
        return False


def create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"username": payload.get("sub")}
    except JWTError:
        return {}


def setup_required() -> bool:
    return not AUTH_FILE.exists()