# server/api/routers/auth.py
from __future__ import annotations
from typing import Optional, Tuple, List

import hashlib
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import secrets

from ..db import users_repo
from ..db.devices_repo import upsert_device, is_revoked, mark_seen
from ..services.password import verify_password, hash_password
from ..services.email_service import send_email
from ..services.device_token import make_device_token, verify_device_token
from ..services import totp_service as TOTP
from ..core.config import settings
from ..db.mongo import users_col  # 이메일 코드(6자리) 저장/조회용으로 직접 사용

router = APIRouter()

# ----- signers (기존: 이메일 링크 검증/디바이스 승인 링크에서 사용) -----
email_signer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="email-verify")
device_signer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="device-approve")

# ----- device cookie settings -----
DEVICE_COOKIE_NAME = getattr(settings, "DEVICE_COOKIE_NAME", "devtk")
DEVICE_COOKIE_SECURE = bool(getattr(settings, "DEVICE_COOKIE_SECURE", False))
DEVICE_COOKIE_SAMESITE = getattr(settings, "DEVICE_COOKIE_SAMESITE", getattr(settings, "COOKIE_SAMESITE", "lax"))
DEVICE_TOKEN_EXPIRE_DAYS = int(getattr(settings, "DEVICE_TOKEN_EXPIRE_DAYS", 180))
COOKIE_DOMAIN: Optional[str] = getattr(settings, "COOKIE_DOMAIN", None)

# ----- 이메일 코드(6자리) 정책 -----
EMAIL_CODE_TTL_MIN = int(getattr(settings, "EMAIL_CODE_TTL_MINUTES", 10))
EMAIL_CODE_MAX_TRIES = int(getattr(settings, "EMAIL_CODE_MAX_TRIES", 5))

# 로그인 단계에서 임시로 들고 있을 세션 키(비번+기기 통과 후 OTP 단계용)
S_PRE_UID = "pre_uid"
S_PRE_EMAIL = "pre_email"
S_PRE_DID = "pre_did"

PASS_MIN = 10
PASS_MAX = 128


# ===== 모델 =====
class LoginReq(BaseModel):
    email: str
    password: str
    dev_id: Optional[str] = None  # 프론트에서 생성한 디바이스 UUID


class RegisterReq(BaseModel):
    email: EmailStr
    password: str


class TotpCode(BaseModel):
    code: str


class EmailCodeSend(BaseModel):
    email: EmailStr


class EmailCodeVerify(BaseModel):
    email: EmailStr
    code: str


# ===== 헬퍼 =====
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


def build_device_approve_link(request: Request, uid: str, email: str, dev_id: str) -> str:
    token = device_signer.dumps({"uid": uid, "email": email, "did": dev_id})
    base = str(request.base_url).rstrip("/")  # 예: http://127.0.0.1:8000
    return f"{base}/auth/device/approve?token={token}"


def to_aware_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Mongo에서 읽은 datetime이 naive면 UTC로 지정, aware면 UTC로 변환."""
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _finalize_login(response: Response, request: Request, u: dict, did: Optional[str]) -> None:
    """세션 확정 + devtk 쿠키 보장 + devices.lastSeen 업데이트"""
    uid = str(u["_id"])
    request.session.clear()
    request.session["uid"] = uid
    request.session["email"] = u.get("email") or u.get("email_norm")

    # devtk 쿠키가 없고 did가 있으면(이 브라우저를 신뢰) 새로 발급
    dev_cookie = request.cookies.get(DEVICE_COOKIE_NAME)
    if not dev_cookie and did:
        token_val = make_device_token(uid, did)
        response.set_cookie(
            key=DEVICE_COOKIE_NAME,
            value=token_val,
            httponly=True,
            secure=DEVICE_COOKIE_SECURE,
            samesite=DEVICE_COOKIE_SAMESITE,
            max_age=DEVICE_TOKEN_EXPIRE_DAYS * 24 * 3600,
            domain=COOKIE_DOMAIN if COOKIE_DOMAIN else None,
            path="/",
        )

    if did:
        mark_seen(uid, did)


def _gen_email_code() -> str:
    # 6자리 숫자
    return f"{secrets.randbelow(10**6):06d}"


def _store_email_code(user_id: str, code: str):
    now = datetime.now(timezone.utc)
    users_col().update_one(
        {"_id": users_repo.ObjectId(user_id)},
        {
            "$set": {
                "email_verified": False,
                "email_code": {
                    "value": code,
                    "tries": 0,
                    "max_tries": EMAIL_CODE_MAX_TRIES,
                    "sent_at": now,
                    "expires_at": now + timedelta(minutes=EMAIL_CODE_TTL_MIN),
                },
                "updatedAt": now,
            }
        },
    )


def _send_email_code(email: str, code: str):
    html = f"""
        <h3>이메일 인증 코드</h3>
        <p>아래 6자리 코드를 앱에서 입력해 이메일 인증을 완료하세요.</p>
        <p style="font-size:20px;font-weight:bold;letter-spacing:2px">{code}</p>
        <p>유효시간: {EMAIL_CODE_TTL_MIN}분</p>
    """
    send_email(email, "Your verification code", html, text=f"Your code: {code}")


# ===== 엔드포인트 =====

@router.post("/auth/register")
def register(body: RegisterReq):
    """
    회원가입:
      - 사용자 생성
      - 6자리 이메일 인증코드 생성/발송 (링크 대신)
      - (이 단계에서는 TOTP QR을 바로 주지 않음. 코드 검증 성공 시 QR 제공)
    """
    email = str(body.email)
    email_norm = normalize_email(email)
    validate_password(body.password, email_norm)

    if users_repo.get_by_email_norm(email_norm):
        raise HTTPException(status_code=409, detail="Email already registered")

    uid = users_repo.insert_user(email, email_norm, hash_password(body.password))

    code = _gen_email_code()
    _store_email_code(uid, code)
    _send_email_code(email, code)

    return {"ok": True, "message": "Verification code sent to your email."}


@router.post("/auth/send-email-code")
def send_email_code(body: EmailCodeSend):
    """
    (재)발송: 가입된 이메일에 6자리 코드를 다시 보냄
    """
    email = str(body.email)
    email_norm = normalize_email(email)
    u = users_repo.get_by_email_norm(email_norm)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    code = _gen_email_code()
    _store_email_code(str(u["_id"]), code)
    _send_email_code(u.get("email") or email, code)
    return {"ok": True, "message": "Verification code re-sent."}


@router.post("/auth/verify-email-code")
def verify_email_code(body: EmailCodeVerify):
    """
    이메일 6자리 코드 검증:
      - 코드/만료/시도횟수 확인
      - 성공 시 email_verified=True
      - 동시에 TOTP 임시 secret 생성해 QR 정보 반환(가입자에게 앱 등록 유도)
    """
    email = str(body.email)
    email_norm = normalize_email(email)
    u = users_repo.get_by_email_norm(email_norm)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    code_info = (u.get("email_code") or {})
    val = (code_info.get("value") or "").strip()
    tries = int(code_info.get("tries") or 0)
    max_tries = int(code_info.get("max_tries") or EMAIL_CODE_MAX_TRIES)
    expires_at = to_aware_utc(code_info.get("expires_at"))

    now = datetime.now(timezone.utc)
    if not val or not expires_at or now > expires_at:
        raise HTTPException(status_code=400, detail="Code expired")
    if tries >= max_tries:
        raise HTTPException(status_code=429, detail="Too many attempts")

    if body.code.strip() != val:
        # 틀린 경우 시도수 증가
        users_col().update_one(
            {"_id": u["_id"]},
            {"$inc": {"email_code.tries": 1}, "$set": {"updatedAt": now}},
        )
        raise HTTPException(status_code=400, detail="Invalid code")

    # 성공: 이메일 인증 완료 + 코드 제거
    users_col().update_one(
        {"_id": u["_id"]},
        {
            "$set": {"email_verified": True, "updatedAt": now},
            "$unset": {"email_code": ""},
        },
    )

    # TOTP 임시 secret 발급 -> QR 정보 반환
    temp_secret = TOTP.gen_base32_secret()
    users_repo.set_totp_temp_secret(str(u["_id"]), temp_secret)
    otpauth = TOTP.build_otpauth_url(temp_secret, account_name=u.get("email") or email)

    return {"ok": True, "message": "Email verified.",
            "totp": {"secret": temp_secret, "otpauth_url": otpauth}}


@router.get("/me")
def me(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return {"ok": True, "user": None}
    return {"ok": True, "user": {"id": uid, "email": request.session.get("email")}}


@router.post("/auth/login")
def login(body: LoginReq, request: Request, response: Response):
    """
    1) 비밀번호 검증
    2) devtk 쿠키로 신뢰 기기 확인 (또는 dev_id로 이메일 승인 진행)
    3) 신뢰 기기 OK면 OTP 단계로 진입
       - totp_enabled=False면 'activate_totp' 단계(가입/검증 후 첫 활성화)
       - totp_enabled=True면 'otp' 단계
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
    tok = verify_device_token(dev_cookie) if dev_cookie else None
    if tok:
        tok_uid, tok_did = tok
        if tok_uid == uid and not is_revoked(uid, tok_did):
            # → 신뢰된 기기. OTP 단계로 이동.
            request.session[S_PRE_UID] = uid
            request.session[S_PRE_EMAIL] = u.get("email") or email_norm
            request.session[S_PRE_DID] = tok_did

            mfa = (u.get("mfa") or {})
            if mfa.get("totp_enabled"):
                return {"ok": True, "next": "otp"}  # OTP 입력 요구
            else:
                # 미활성화 → QR 재노출 + 첫 코드 인증
                temp = mfa.get("totp_temp_secret") or TOTP.gen_base32_secret()
                if not mfa.get("totp_temp_secret"):
                    users_repo.set_totp_temp_secret(uid, temp)
                return {
                    "ok": True,
                    "next": "activate_totp",
                    "totp": {"secret": temp, "otpauth_url": TOTP.build_otpauth_url(temp, u.get("email") or email_norm)}
                }

    # 2) devtk 없음/무효 → dev_id 필요 & 이메일 승인 진행
    dev_id = (body.dev_id or "").strip()
    if not dev_id:
        return {"ok": True, "device_required": True, "reason": "need_dev_id"}

    link = build_device_approve_link(request, uid, u.get("email") or email_norm, dev_id)
    html = f"""
      <h3>Approve new device</h3>
      <p>To complete sign-in on a new device, click:</p>
      <p><a href="{link}">{link}</a></p>
      <p>If this wasn't you, ignore this email.</p>
    """
    send_email(u.get("email") or email_norm, "Approve new device", html, text=f"Approve: {link}")

    return {"ok": True, "device_required": True, "message": "Approval email sent. Open the link in this browser and try again."}


@router.post("/auth/mfa/totp/activate")
def activate_totp_login(body: TotpCode, request: Request, response: Response):
    """
    로그인 진행 중(비번 + 신뢰 기기 통과 후) 최초 TOTP 활성화 & 로그인 완료
    - 세션에 S_PRE_UID 가 있어야 함
    """
    pre_uid = request.session.get(S_PRE_UID)
    pre_email = request.session.get(S_PRE_EMAIL)
    pre_did = request.session.get(S_PRE_DID)
    if not pre_uid:
        raise HTTPException(status_code=400, detail="No pending login")

    u = users_repo.get_by_id(pre_uid)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    mfa = (u.get("mfa") or {})
    temp_secret = mfa.get("totp_temp_secret")
    if not temp_secret:
        raise HTTPException(status_code=400, detail="No TOTP to activate")

    ok, step = TOTP.verify_totp(temp_secret, body.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    # 백업코드 생성 & 저장
    backups = TOTP.gen_backup_codes()
    backup_hashes = [TOTP.hash_backup_code(c) for c in backups]
    users_repo.activate_totp(pre_uid, temp_secret, backup_hashes)
    users_repo.set_last_counter(pre_uid, int(step))

    # 최종 로그인 확정
    _finalize_login(response, request, u, pre_did)

    # 프런트에 실제 백업코드(평문) 1회 제공
    return {"ok": True, "backup_codes": backups}


@router.post("/auth/mfa/totp/verify-login")
def verify_totp_login(body: TotpCode, request: Request, response: Response):
    """
    로그인 진행 중(비번 + 신뢰 기기 통과 후) OTP 검증 & 로그인 완료
    - 세션에 S_PRE_UID 가 있어야 함
    - 리플레이 방지: last_counter < step 여야 함
    """
    pre_uid = request.session.get(S_PRE_UID)
    pre_did = request.session.get(S_PRE_DID)
    if not pre_uid:
        raise HTTPException(status_code=400, detail="No pending login")

    u = users_repo.get_by_id(pre_uid)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    mfa = (u.get("mfa") or {})
    if not mfa.get("totp_enabled") or not mfa.get("totp_secret"):
        raise HTTPException(status_code=400, detail="TOTP not enabled")

    ok, step = TOTP.verify_totp(mfa["totp_secret"], body.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    # 리플레이 방지
    last = users_repo.get_last_counter(pre_uid)
    if step is None or int(step) <= int(last):
        raise HTTPException(status_code=400, detail="Code already used")
    users_repo.set_last_counter(pre_uid, int(step))

    # 최종 로그인 확정
    _finalize_login(response, request, u, pre_did)
    return {"ok": True}


@router.get("/auth/device/approve")
def approve_device(token: str, request: Request):
    """
    이메일 승인 링크(신규 기기):
      - devtk 쿠키 굽기
      - devices 컬렉션 upsert(UA/IP 해시 기록)
    """
    try:
        data = device_signer.loads(token, max_age=60 * 60 * 24)  # 24h
    except SignatureExpired:
        return HTMLResponse("<h3>Approval link expired.</h3>", status_code=400)
    except BadSignature:
        return HTMLResponse("<h3>Invalid approval link.</h3>", status_code=400)

    uid = data.get("uid"); did = data.get("did")
    if not uid or not did:
        return HTMLResponse("<h3>Invalid payload.</h3>", status_code=400)

    # devtk 세팅
    token_val = make_device_token(uid, did)
    resp = HTMLResponse("<h3>Device approved ✅<br/>Return to the app and login again.</h3>")
    resp.set_cookie(
        key=DEVICE_COOKIE_NAME,
        value=token_val,
        httponly=True,
        secure=DEVICE_COOKIE_SECURE,
        samesite=DEVICE_COOKIE_SAMESITE,
        max_age=DEVICE_TOKEN_EXPIRE_DAYS * 24 * 3600,
        domain=COOKIE_DOMAIN if COOKIE_DOMAIN else None,
        path="/",
    )

    # 디바이스 메타 기록(선택)
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
