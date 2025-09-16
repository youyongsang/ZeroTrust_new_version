# server/api/core/config.py
import os
from pathlib import Path
from dotenv import load_dotenv

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(ENV_PATH if ENV_PATH.exists() else None)


def _as_bool(v: str | None, default=False):
    if v is None:
        return default
    return v.lower() in {"1", "true", "yes", "on"}


def _as_list(v: str | None):
    return [s.strip() for s in v.split(",")] if v else []


class Settings:
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "8000"))

    SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret")
    COOKIE_NAME = os.getenv("COOKIE_NAME", "authmin_session")
    COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")  # lax/strict/none
    COOKIE_SECURE = _as_bool(os.getenv("COOKIE_SECURE"), False)

    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME = os.getenv("DB_NAME", "auth_min")

    CORS_ORIGINS = _as_list(os.getenv("CORS_ORIGINS"))  # 예: http://localhost:5500

    # Email verification
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
    SITE_BASE_URL = os.getenv("SITE_BASE_URL", "http://localhost:8000")
    EMAIL_TOKEN_EXPIRE_HOURS = int(os.getenv("EMAIL_TOKEN_EXPIRE_HOURS", "24"))

    # SMTP
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "0") or 0)
    SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "false").lower() == "true"
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "noreply@example.com")

    SITE_BASE_URL = os.getenv("SITE_BASE_URL", "http://localhost:8000")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
    EMAIL_TOKEN_EXPIRE_HOURS = int(os.getenv("EMAIL_TOKEN_EXPIRE_HOURS", "24"))

        # 추가: 디바이스 토큰 쿠키/만료
    DEVICE_COOKIE_NAME = "devtk"
    DEVICE_COOKIE_SECURE = COOKIE_SECURE            # 배포시 True 권장
    DEVICE_COOKIE_SAMESITE = COOKIE_SAMESITE        # "lax" 권장
    DEVICE_TOKEN_SECRET = SECRET_KEY + "_device"
    DEVICE_TOKEN_EXPIRE_DAYS = 180                  # 6개월 정도

settings = Settings()
