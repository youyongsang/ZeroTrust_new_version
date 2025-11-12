# server/api/main.py
from typing import List, Union
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles

from .core.config import settings
from .routers import auth as auth_router
from .routers.admin import router as admin_router


def _parse_cors_origins(val: Union[str, List[str], None]) -> List[str]:
    """
    settings.CORS_ORIGINS 가 콤마로 연결된 문자열이든, 리스트든, None 이든
    안전하게 List[str] 로 변환한다.
    """
    if not val:
        return []
    if isinstance(val, str):
        return [o.strip() for o in val.split(",") if o.strip()]
    return [o.strip() for o in val if isinstance(o, str) and o.strip()]


app = FastAPI(title="auth-min (device-based login demo)")

# --- CORS ---
# 기본값을 127.0.0.1로 통일 (정적서버를 :5500에서 띄우는 경우 대비)
_default_cors = [
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5500",
]
allow_origins = _parse_cors_origins(getattr(settings, "CORS_ORIGINS", None)) or _default_cors

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,  # 세션/장치 쿠키 사용을 위해 필수
)

# --- 세션 쿠키 ---
# SameSite / Secure 설정은 .env 의 COOKIE_SAMESITE / COOKIE_SECURE 를 따른다.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET,
    session_cookie=settings.COOKIE_NAME,
    same_site=settings.COOKIE_SAMESITE,   # "lax" / "strict" / "none"
    https_only=settings.COOKIE_SECURE,    # 로컬 개발이면 false
)

# --- API 라우터 ---
app.include_router(auth_router.router)
app.include_router(admin_router)

# --- 정적 프론트 서빙 ---
# 프로젝트 루트에 있는 web/ 폴더를 루트 경로에 마운트
WEB_DIR = Path(__file__).resolve().parents[2] / "web"
app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")

# (선택) 헬스체크
# @app.get("/api/health")
# def health():
#     return {"ok": True}
