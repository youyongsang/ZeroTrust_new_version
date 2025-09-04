# server/api/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
from fastapi.staticfiles import StaticFiles

from .core.config import settings
from .routers import auth as auth_router

app = FastAPI(title="auth-min (login/logout only)")

# CORS (같은 오리진에서 서빙하면 사실 필요 없음, 있어도 무방)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS or ["http://localhost:5500"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# 세션 쿠키
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET,
    session_cookie=settings.COOKIE_NAME,
    same_site=settings.COOKIE_SAMESITE,
    https_only=settings.COOKIE_SECURE,
)

# API 라우터 먼저 등록
app.include_router(auth_router.router)

# 정적 프론트 서빙(맨 마지막에 마운트)
WEB_DIR = Path(__file__).resolve().parents[2] / "web"
app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")

# (선택) 헬스체크를 따로 두고 싶으면 /api/health 처럼 별도 경로로:
# @app.get("/api/health")
# def health():
#     return {"ok": True}
