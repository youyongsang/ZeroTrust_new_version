# server/api/routers/auth.py
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import hashlib
import logging
import time
from typing import Optional, Tuple

from ..db import users_repo
from ..db.devices_repo import upsert_device, is_revoked, mark_seen
from ..services.password import verify_password, hash_password
from ..services.email_service import send_email
from ..services.device_token import make_device_token, verify_device_token
from ..core.config import settings

log = logging.getLogger("uvicorn.error")
router = APIRouter()

# ----- token signers -----
email_signer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="email-verify")
device_signer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="device-approve")

# ----- settings (기본값 포함/정규화) -----
DEVICE_COOKIE_NAME = getattr(settings, "DEVICE_COOKIE_NAME", "devtk")
DEVICE_COOKIE_SECURE: bool = bool(getattr(settings, "DEVICE_COOKIE_SECURE", False))
# Starlette는 소문자 'lax|strict|none'을 권장
DEVICE_COOKIE_SAMESITE: str = str(
    getattr(settings, "DEVICE_COOKIE_SAMESITE", getattr(settings, "COOKIE_SAMESITE", "lax"))
).lower()
DEVICE_TOKEN_EXPIRE_DAYS: int = int(getattr(settings, "DEVICE_TOKEN_EXPIRE_DAYS", 180))
# 공백 문자열이면 None 취급
_COOKIE_DOMAIN_RAW = getattr(settings, "COOKIE_DOMAIN", None)
COOKIE_DOMAIN: Optional[str] = _COOKIE_DOMAIN_RAW if _COOKIE_DOMAIN_RAW else None

PASS_MIN = 10
PASS_MAX = 128


# ----- models -----
class LoginReq(BaseModel):
    email: str
    password: str
    dev_id: Optional[str] = None  # 프론트에서 생성한 브라우저 고유값


class RegisterReq(BaseModel):
    email: EmailStr
    password: str


# ----- helpers -----
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def validate_password(pw: str, email_norm: str):
    if len(pw) < PASS_MIN:
        raise HTTPException(status_code=400, detail=f"Password must be at least {PASS_MIN} chars")
    if len(pw) > PASS_MAX:
        raise HTTPException(status_code=400, detail=f"Password must be at most {PASS_MAX} chars")
    local = email_norm.split("@")[0]
    if local and local in pw.lower():
        raise HTTPException(status_code=400, detail="Password must not contain your email name")


def build_verify_link(email: str) -> str:
    token = email_signer.dumps({"email": normalize_email(email)})
    return f"{settings.SITE_BASE_URL}/auth/verify?token={token}"


def build_device_approve_link(request: Request, uid: str, email: str, dev_id: str) -> str:
    """요청이 온 호스트(127 or localhost)에 맞춰 링크 생성"""
    token = device_signer.dumps({"uid": uid, "email": email, "did": dev_id})
    base = str(request.base_url).rstrip("/")  # 예: http://127.0.0.1:8000
    return f"{base}/auth/device/approve?token={token}"


# ====== endpoints ======
@router.post("/auth/register")
def register(body: RegisterReq):
    email = str(body.email)
    email_norm = normalize_email(email)
    validate_password(body.password, email_norm)

    if users_repo.get_by_email_norm(email_norm):
        raise HTTPException(status_code=409, detail="Email already registered")

    pw_hash = hash_password(body.password)
    users_repo.insert_user(email, email_norm, pw_hash)

    link = build_verify_link(email)
    html = f"""
      <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f9f9f9; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
        <h2 style="color: #2d7ff9;">이메일 인증 안내</h2>
        <p style="font-size: 1.1em;">안녕하세요,<br>
        회원가입을 완료하려면 아래 버튼을 눌러 이메일 인증을 진행해 주세요.</p>
        <a href="{link}" style="display:inline-block; background:#2d7ff9; color:#fff; padding:12px 24px; border-radius:6px; text-decoration:none; font-weight:bold; margin:16px 0;">이메일 인증하기</a>
        <p style="font-size:0.95em; color:#555;">이 링크는 {settings.EMAIL_TOKEN_EXPIRE_HOURS}시간 동안만 유효합니다.<br>
        문의: 20211884@edu.hanbat.ac.kr</p>
      </div>
    """
    send_email(email, "이메일 인증 안내", html, text=f"인증: {link}")
    return {"ok": True, "message": "회원가입 완료! 이메일을 확인해 인증을 진행해 주세요."}


@router.get("/auth/verify")
def verify_email(token: str):
    try:
        data = email_signer.loads(token, max_age=60 * 60 * settings.EMAIL_TOKEN_EXPIRE_HOURS)
    except SignatureExpired:
        return HTMLResponse("""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #fff3f3; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
            <h2 style="color: #e74c3c;">인증 링크 만료</h2>
            <p>인증 링크가 만료되었습니다. 다시 회원가입을 진행해 주세요.</p>
        </div>
        """, status_code=400)
    except BadSignature:
        return HTMLResponse("""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #fff3f3; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
            <h2 style="color: #e74c3c;">잘못된 인증 링크</h2>
            <p>인증 링크가 올바르지 않습니다.</p>
        </div>
        """, status_code=400)

    email_norm = data.get("email")
    if not email_norm:
        return HTMLResponse("""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #fff3f3; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
            <h2 style="color: #e74c3c;">잘못된 토큰 정보</h2>
            <p>토큰 정보가 올바르지 않습니다.</p>
        </div>
        """, status_code=400)

    u = users_repo.get_by_email_norm(email_norm)
    if not u:
        return HTMLResponse("""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #fff3f3; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
            <h2 style="color: #e74c3c;">사용자를 찾을 수 없음</h2>
            <p>해당 이메일의 사용자가 존재하지 않습니다.</p>
        </div>
        """, status_code=404)

    if u.get("email_verified"):
        return HTMLResponse("""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f9f9f9; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
            <h2 style="color: #2d7ff9;">이미 인증됨</h2>
            <p>이메일 인증이 이미 완료되었습니다.</p>
        </div>
        """)

    users_repo.set_email_verified(email_norm)
    return HTMLResponse("""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f9f9f9; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
        <h2 style="color: #2d7ff9;">인증 완료!</h2>
        <p>이메일 인증이 성공적으로 완료되었습니다.<br>이제 로그인하실 수 있습니다.</p>
    </div>
    """)


@router.get("/me")
def me(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return {"ok": True, "user": None}
    return {"ok": True, "user": {"id": uid, "email": request.session.get("email")}}


# 인증 메일 발송 기록 (메모리 캐시, 실제 서비스는 Redis 등 사용 권장)
DEVICE_APPROVE_CACHE = {}

DEVICE_APPROVE_COOLDOWN_SEC = 60  # 1분 쿨타임 (원하는 시간으로 조정)

@router.post("/auth/login")
def login(body: LoginReq, request: Request, response: Response):
    """
    1) 비밀번호 검증
    2) devtk 쿠키 유효 → 세션 로그인
    3) 없거나 유효X → dev_id 필수, 승인 메일 발송 → device_required
    """
    email_norm = normalize_email(body.email)
    if not email_norm or not body.password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    u = users_repo.get_by_email_norm(email_norm)
    if not u or not verify_password(body.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not u.get("email_verified", False):
        raise HTTPException(status_code=403, detail="Email not verified")

    uid = str(u["_id"])

    # 1) devtk 쿠키 검사
    dev_cookie = request.cookies.get(DEVICE_COOKIE_NAME)
    log.debug(f"[login] has_dev_cookie={bool(dev_cookie)} email={email_norm}")
    if dev_cookie:
        verified: Optional[Tuple[str, str]] = verify_device_token(dev_cookie)
        log.debug(f"[login] token_verified={verified}")
        if verified:
            tok_uid, tok_did = verified
            if tok_uid == uid and not is_revoked(uid, tok_did):
                request.session.clear()
                request.session["uid"] = uid
                request.session["email"] = u.get("email") or email_norm
                mark_seen(uid, tok_did)
                return {"ok": True}
            else:
                # 디버깅 도움용 reason
                reason = "uid_mismatch_or_revoked"
                return {"ok": True, "device_required": True, "reason": reason}

    # 2) 신규 기기 → dev_id 필요
    dev_id = (body.dev_id or "").strip()
    if not dev_id:
        return {"ok": True, "device_required": True, "reason": "cookie_missing_or_need_dev_id"}

    # 쿨타임 체크
    cache_key = f"{email_norm}:{dev_id}"
    now = time.time()
    last_sent = DEVICE_APPROVE_CACHE.get(cache_key, 0)
    if now - last_sent < DEVICE_APPROVE_COOLDOWN_SEC:
        return {
            "ok": False,
            "device_required": True,
            "message": f"최근에 이미 인증 메일을 보냈습니다. 잠시 후 다시 시도해 주세요.",
            "dev_id": dev_id,
        }
    DEVICE_APPROVE_CACHE[cache_key] = now

    # 승인 링크 발송
    link = build_device_approve_link(request, uid, u.get("email") or email_norm, dev_id)
    html = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f9f9f9; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
        <h2 style="color: #2d7ff9;">새 기기 로그인 승인</h2>
        <p style="font-size: 1.1em;">안녕하세요,<br>
        새로운 기기에서 로그인 시도가 감지되었습니다.<br>
        아래 버튼을 눌러 기기 승인을 완료하세요.</p>
        <a href="{link}" style="display:inline-block; background:#2d7ff9; color:#fff; padding:12px 24px; border-radius:6px; text-decoration:none; font-weight:bold; margin:16px 0;">기기 승인하기</a>
        <p style="font-size:0.95em; color:#555;">만약 본인이 아니라면 이 이메일을 무시하세요.<br>
        문의: 20211884@edu.hanbat.ac.kr</p>
    </div>
    """
    send_email(u.get("email") or email_norm, "새 기기 로그인 승인 안내", html, text=f"Approve: {link}")

    return {"ok": True, "device_required": True, "message": "Check your email and approve this device.", "dev_id": dev_id}


@router.get("/auth/device/approve")
def approve_device(token: str, request: Request):
    """
    이메일 승인 링크:
      - 토큰 검증 OK → devtk 쿠키 굽기
      - devices 컬렉션 upsert(UA/IP 해시 기록)
    """
    try:
        data = device_signer.loads(token, max_age=60 * 60 * 24)  # 24h 유효
    except SignatureExpired:
        return HTMLResponse("<h3>Approval link expired.</h3>", status_code=400)
    except BadSignature:
        return HTMLResponse("<h3>Invalid approval link.</h3>", status_code=400)

    uid = data.get("uid")
    did = data.get("did")
    if not uid or not did:
        return HTMLResponse("<h3>Invalid payload.</h3>", status_code=400)

    # devtk(장기쿠키) 생성 & 굽기
    token_val = make_device_token(uid, did)
    resp = HTMLResponse("""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f9f9f9; padding: 32px; border-radius: 12px; max-width: 480px; margin: auto;">
        <h2 style="color: #2d7ff9;">기기 승인 완료 ✅</h2>
        <p>기기 인증이 완료되었습니다.<br>앱으로 돌아가 다시 로그인해 주세요.</p>
    </div>
    """)

    cookie_kwargs = dict(
        key=DEVICE_COOKIE_NAME,
        value=token_val,
        httponly=True,
        secure=DEVICE_COOKIE_SECURE,
        samesite=DEVICE_COOKIE_SAMESITE,  # 'lax'|'strict'|'none'
        max_age=DEVICE_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/",
    )
    if COOKIE_DOMAIN:
        cookie_kwargs["domain"] = COOKIE_DOMAIN
    resp.set_cookie(**cookie_kwargs)

    # UA/IP 해시 저장 (옵션)
    ua_raw = (request.headers.get("user-agent") or "").encode("utf-8")
    ip_raw = (request.client.host if request.client else "").encode("utf-8")
    ua_hash = hashlib.sha256(ua_raw).hexdigest() if ua_raw else None
    ip_hash = hashlib.sha256(ip_raw).hexdigest() if ip_raw else None

    try:
        upsert_device(uid, did, label=None, ua_hash=ua_hash, ip_hash=ip_hash)
    except Exception as e:
        log.debug(f"[approve_device] upsert_device failed: {e!r}")

    return resp


@router.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}
