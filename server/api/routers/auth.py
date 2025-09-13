# server/api/routers/auth.py
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta
import secrets, pyotp

from ..db import users_repo
from ..services.password import verify_password, hash_password
from ..services.email_service import send_email
from ..core.config import settings

router = APIRouter()

# ===== models =====
class RegisterStartReq(BaseModel):
    email: EmailStr
    password: str

class EmailCodeReq(BaseModel):
    code: str

class OtpCodeReq(BaseModel):
    code: str

class LoginReq(BaseModel):
    email: str
    password: str

# ===== helpers =====
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

PASS_MIN, PASS_MAX = 10, 128
def validate_password(pw: str, email_norm: str):
    if len(pw) < PASS_MIN:
        raise HTTPException(400, f"Password must be at least {PASS_MIN} chars")
    if len(pw) > PASS_MAX:
        raise HTTPException(400, f"Password must be at most {PASS_MAX} chars")
    local = email_norm.split("@")[0]
    if local and local in pw.lower():
        raise HTTPException(400, "Password must not contain your email name")

def _rand_code(n=6) -> str:
    return f"{secrets.randbelow(10**n):0{n}d}"

def _reg_session(request: Request) -> dict:
    return request.session.setdefault("reg", {})

# ===== 기존: 이메일 링크 검증 제거 =====
# 회원가입은 3단계로 진행:
#  (1) /auth/register/start  → 이메일로 6자리 코드 발송(또는 콘솔 출력)
#  (2) /auth/register/verify-email-code → 코드 통과 시 TOTP secret 발급(otpauth URI 반환)
#  (3) /auth/register/activate-totp → 첫 OTP 검증 성공 시 DB에 사용자 생성(+백업코드 발급)

@router.post("/auth/register/start")
def register_start(body: RegisterStartReq, request: Request):
    email = str(body.email)
    email_norm = normalize_email(email)
    validate_password(body.password, email_norm)

    if users_repo.get_by_email_norm(email_norm):
        raise HTTPException(409, "Email already registered")

    # 세션에 임시 가입 상태 저장
    reg = {
        "email": email,
        "email_norm": email_norm,
        "pw_hash": hash_password(body.password),
        "email_code": _rand_code(6),
        "email_code_exp": (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
        "email_code_tries": 0,
        "created": datetime.utcnow().isoformat(),
    }
    request.session["reg"] = reg

    # 코드 전송(설정 없으면 콘솔 출력)
    html = f"<h3>Your verification code</h3><p><b>{reg['email_code']}</b> (10분 유효)</p>"
    send_email(email, "Your verification code", html, text=f"code: {reg['email_code']}")

    return {"ok": True, "next": "enter_email_code"}

@router.post("/auth/register/verify-email-code")
def register_verify_email_code(body: EmailCodeReq, request: Request):
    reg = request.session.get("reg")
    if not reg:
        raise HTTPException(400, "Registration session not found")

    # 만료 체크
    if datetime.utcnow() > datetime.fromisoformat(reg["email_code_exp"]):
        request.session.pop("reg", None)
        raise HTTPException(400, "Verification code expired")

    # 시도 제한
    tries = int(reg.get("email_code_tries", 0))
    if tries >= 5:
        request.session.pop("reg", None)
        raise HTTPException(429, "Too many attempts")

    if body.code.strip() != reg["email_code"]:
        reg["email_code_tries"] = tries + 1
        request.session["reg"] = reg
        raise HTTPException(400, "Invalid verification code")

    # 통과 → TOTP 임시 시크릿 발급
    secret = pyotp.random_base32()
    reg["totp_temp_secret"] = secret
    request.session["reg"] = reg

    otpauth_url = pyotp.TOTP(secret).provisioning_uri(
        name=reg["email"],
        issuer_name=settings.ISSUER_NAME,
    )
    return {"ok": True, "secret": secret, "otpauth_url": otpauth_url, "next": "scan_qr_and_enter_otp"}

@router.post("/auth/register/activate-totp")
def register_activate_totp(body: OtpCodeReq, request: Request):
    reg = request.session.get("reg")
    if not reg or not reg.get("totp_temp_secret"):
        raise HTTPException(400, "No TOTP pending setup")

    vw = getattr(settings, "TOTP_VALID_WINDOW", 1)
    ok = pyotp.TOTP(reg["totp_temp_secret"]).verify(body.code.strip(), valid_window=vw)
    if not ok:
        raise HTTPException(400, "Invalid OTP")

    # 백업코드 생성(평문은 응답, DB에는 해시 저장)
    codes_plain, hashes = users_repo.generate_backup_codes(
        count=settings.BACKUP_CODE_COUNT,
        pepper=settings.BACKUP_CODE_PEPPER,
    )

    # 최종 사용자 생성(이메일 검증 완료 + MFA 활성화)
    uid = users_repo.insert_user_with_mfa(
        email=reg["email"],
        email_norm=reg["email_norm"],
        pw_hash=reg["pw_hash"],
        totp_secret=reg["totp_temp_secret"],
        backup_hashes=hashes,
    )

    # 세션 정리 + 로그인 완료 처리
    request.session.pop("reg", None)
    request.session.clear()
    request.session["uid"] = str(uid)
    request.session["email"] = reg["email"]

    return {"ok": True, "backup_codes": codes_plain}

# ===== 로그인(이후에는 항상 2단계 요구) =====
@router.post("/auth/login")
def login(body: LoginReq, request: Request):
    email_norm = normalize_email(body.email)
    if not email_norm or not body.password:
        raise HTTPException(400, "Email and password are required")

    u = users_repo.get_by_email_norm(email_norm)
    if not u or not verify_password(body.password, u.get("password_hash", "")):
        raise HTTPException(401, "Invalid credentials")

    # MFA가 반드시 켜져 있어야 함(가입 시 강제)
    mfa = (u.get("mfa") or {})
    if not (mfa.get("totp_enabled") and mfa.get("totp_secret")):
        raise HTTPException(403, "Account not fully enrolled for MFA")

    # 2단계 요구 세션
    request.session.clear()
    request.session["mfa_uid"] = str(u["_id"])
    request.session["mfa_tries"] = 0
    return {"ok": True, "mfa_required": True, "method": "totp"}

@router.post("/auth/mfa/totp/verify-login")
def verify_login_totp(body: OtpCodeReq, request: Request):
    uid = request.session.get("mfa_uid")
    if not uid:
        raise HTTPException(401, "MFA session not found")

    u = users_repo.get_by_id(uid)
    if not u:
        raise HTTPException(404, "User not found")

    mfa = u.get("mfa") or {}
    secret = mfa.get("totp_secret")
    if not (mfa.get("totp_enabled") and secret):
        raise HTTPException(400, "TOTP not enabled")

    tries = int(request.session.get("mfa_tries") or 0)
    if tries >= 5:
        raise HTTPException(429, "Too many OTP attempts")

    vw = getattr(settings, "TOTP_VALID_WINDOW", 1)
    if not pyotp.TOTP(secret).verify(body.code.strip(), valid_window=vw):
        request.session["mfa_tries"] = tries + 1
        raise HTTPException(400, "Invalid OTP")

    request.session.clear()
    request.session["uid"] = str(u["_id"])
    request.session["email"] = u.get("email") or u.get("email_norm")
    return {"ok": True}

@router.get("/me")
def me(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return {"ok": True, "user": None}
    return {"ok": True, "user": {"id": uid, "email": request.session.get("email")}}

@router.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}
