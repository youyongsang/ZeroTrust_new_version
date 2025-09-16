# server/api/routers/auth.py
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import hashlib

from ..db import users_repo
from ..db.devices_repo import upsert_device, is_revoked, mark_seen  # ★ 추가
from ..services.password import verify_password, hash_password
from ..services.email_service import send_email
from ..services.device_token import make_device_token, verify_device_token  # ★ 추가
from ..core.config import settings

router = APIRouter()

# ----- token signers -----
email_signer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="email-verify")
device_signer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="device-approve")  # ★ 새 기기 승인 토큰

# ----- settings fallback (없어도 동작하도록 기본값) -----
DEVICE_COOKIE_NAME = getattr(settings, "DEVICE_COOKIE_NAME", "devtk")
DEVICE_COOKIE_SECURE = getattr(settings, "DEVICE_COOKIE_SECURE", False)
DEVICE_COOKIE_SAMESITE = getattr(settings, "DEVICE_COOKIE_SAMESITE", getattr(settings, "COOKIE_SAMESITE", "lax"))
DEVICE_TOKEN_EXPIRE_DAYS = getattr(settings, "DEVICE_TOKEN_EXPIRE_DAYS", 180)

# ----- models -----
class LoginReq(BaseModel):
    email: str
    password: str
    dev_id: str | None = None   # ★ 프론트에서 넘기는 브라우저 고유값

class RegisterReq(BaseModel):
    email: EmailStr
    password: str

# ----- helpers -----
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

PASS_MIN = 10
PASS_MAX = 128

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
    # handled by GET /auth/verify
    return f"{settings.SITE_BASE_URL}/auth/verify?token={token}"

def build_device_approve_link(uid: str, email: str, dev_id: str) -> str:
    token = device_signer.dumps({"uid": uid, "email": email, "did": dev_id})
    return f"{settings.SITE_BASE_URL}/auth/device/approve?token={token}"

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
      <h3>Verify your email</h3>
      <p>Click the link to verify your account:</p>
      <p><a href="{link}">{link}</a></p>
      <p>This link expires in {settings.EMAIL_TOKEN_EXPIRE_HOURS} hours.</p>
    """
    send_email(email, "Verify your email", html, text=f"Verify: {link}")
    return {"ok": True, "message": "Registered. Check your email to verify."}

@router.get("/auth/verify")
def verify_email(token: str):
    try:
        data = email_signer.loads(token, max_age=60*60*settings.EMAIL_TOKEN_EXPIRE_HOURS)
    except SignatureExpired:
        return HTMLResponse("<h3>Verification link expired.</h3>", status_code=400)
    except BadSignature:
        return HTMLResponse("<h3>Invalid verification link.</h3>", status_code=400)

    email_norm = data.get("email")
    if not email_norm:
        return HTMLResponse("<h3>Invalid token payload.</h3>", status_code=400)

    u = users_repo.get_by_email_norm(email_norm)
    if not u:
        return HTMLResponse("<h3>User not found.</h3>", status_code=404)

    if u.get("email_verified"):
        return HTMLResponse("<h3>Email already verified.</h3>")

    users_repo.set_email_verified(email_norm)
    return HTMLResponse("<h3>Email verified! You can close this tab and login.</h3>")

@router.get("/me")
def me(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return {"ok": True, "user": None}
    return {"ok": True, "user": {"id": uid, "email": request.session.get("email")}}

@router.post("/auth/login")
def login(body: LoginReq, request: Request, response: Response):
    """
    1) 비번 검증
    2) 디바이스 토큰 쿠키(devtk) 유효하면 바로 세션 로그인
    3) 없으면 새 기기 승인 메일 발송 → device_required 응답
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

    # 1) 디바이스 토큰 쿠키 확인
    dev_cookie = request.cookies.get(DEVICE_COOKIE_NAME)
    if dev_cookie:
        token_data = verify_device_token(dev_cookie)
        if token_data and token_data.get("uid") == uid and not is_revoked(uid, token_data.get("did", "")):
            # 신뢰된 디바이스 → 세션 로그인 완료
            request.session.clear()
            request.session["uid"] = uid
            request.session["email"] = u.get("email") or email_norm
            mark_seen(uid, token_data["did"])
            return {"ok": True}

    # 2) 새 기기 → dev_id 필수
    dev_id = (body.dev_id or "").strip()
    if not dev_id:
        # 프론트가 dev_id를 생성해서 다시 보내도록 안내
        return {"ok": True, "device_required": True, "reason": "need_dev_id"}

    # 승인 링크 발송 (개발 환경: 콘솔로 출력, 운영: 실제 이메일 발송)
    link = build_device_approve_link(uid, u.get("email") or email_norm, dev_id)
    html = f"""
      <h3>Approve new device</h3>
      <p>To complete sign-in on a new device, click:</p>
      <p><a href="{link}">{link}</a></p>
      <p>If this wasn't you, ignore this email.</p>
    """
    send_email(u.get("email") or email_norm, "Approve new device", html, text=f"Approve: {link}")

    return {"ok": True, "device_required": True, "message": "Check your email and approve this device."}

@router.get("/auth/device/approve")
def approve_device(token: str, request: Request):
    """
    이메일의 승인 링크를 열면:
    - 해당 브라우저에 devtk 쿠키 심기
    - devices 컬렉션 upsert (UA/IP 해시 저장)
    """
    try:
        data = device_signer.loads(token, max_age=60*60*24)  # 24시간 유효
    except SignatureExpired:
        return HTMLResponse("<h3>Approval link expired.</h3>", status_code=400)
    except BadSignature:
        return HTMLResponse("<h3>Invalid approval link.</h3>", status_code=400)

    uid = data.get("uid"); did = data.get("did"); email = data.get("email")
    if not uid or not did:
        return HTMLResponse("<h3>Invalid payload.</h3>", status_code=400)

    # devtk 생성 및 쿠키로 설정
    token_val = make_device_token(uid, did)
    resp = HTMLResponse("<h3>Device approved ✅<br/>Return to the app and login again.</h3>")
    resp.set_cookie(
        key=DEVICE_COOKIE_NAME,
        value=token_val,
        httponly=True,
        secure=DEVICE_COOKIE_SECURE,
        samesite=DEVICE_COOKIE_SAMESITE,
        max_age=DEVICE_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/",
    )

    # UA/IP 해시로 메타 저장
    ua_raw = (request.headers.get("user-agent") or "").encode("utf-8")
    ip_raw = (request.client.host if request.client else "").encode("utf-8")
    ua_hash = hashlib.sha256(ua_raw).hexdigest() if ua_raw else None
    ip_hash = hashlib.sha256(ip_raw).hexdigest() if ip_raw else None

    upsert_device(uid, did, label=None, ua_hash=ua_hash, ip_hash=ip_hash)
    return resp

@router.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}
