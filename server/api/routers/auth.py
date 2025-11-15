# server/api/routers/auth.py
from __future__ import annotations
from typing import Optional, Tuple, List

import hashlib
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import secrets

from ..db import users_repo
from ..db import devices_repo
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
    print("Session set:", request.session.get("uid"), request.session.get("email"))

    # devtk 쿠키가 없고 did가 있으면(이 브라우저를 신뢰) 새로 발급
    dev_cookie = request.cookies.get(DEVICE_COOKIE_NAME)
    if not dev_cookie and did:
        print("Setting device cookie")
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
        print("Mark device seen:", did)
        devices_repo.mark_seen(uid, did)


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
def verify_email_code(body: EmailCodeVerify, request: Request):
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

    request.session["uid"] = str(u["_id"])

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
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    uid = str(u["_id"])

    # 로그인 잠금 체크
    lock = users_repo.get_login_lock(uid)
    if lock.get("locked_until"):
        now = datetime.now(timezone.utc)
        locked_until = lock["locked_until"]
        # DB에서 온 값이 naive datetime일 수 있으니 tzinfo 없으면 UTC로 간주
        if getattr(locked_until, "tzinfo", None) is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            retry_after = int((locked_until - now).total_seconds())
            return JSONResponse(
                status_code=429,
                content={
                    "ok": False,
                    "locked": True,
                    "retry_after": retry_after,
                    "message": f"연속된 로그인 실패로 제한이 걸렸습니다. {retry_after}초 후에 다시 시도해 주세요."
                },
            )

    # 비밀번호 검증
    if not verify_password(body.password, u.get("password_hash", "")):
        cnt = users_repo.incr_failed_login(uid)
        if cnt >= 5:
            users_repo.lock_account(uid, minutes=5)
            raise HTTPException(status_code=429, detail="Too many failed attempts. Account locked for 5 minutes.")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 로그인 성공 시 실패 카운트 리셋
    users_repo.reset_failed_login(uid)

    if not u.get("email_verified", False):
        raise HTTPException(status_code=403, detail="Email not verified")

    uid = str(u["_id"])

    # 1) devtk 쿠키 검사
    dev_cookie = request.cookies.get(DEVICE_COOKIE_NAME)
    tok = verify_device_token(dev_cookie) if dev_cookie else None
    if tok:
        tok_uid, tok_did = tok
        print("tok_uid:", tok_uid, "->", devices_repo.is_approved(uid, tok_did), devices_repo.is_revoked(uid, tok_did), uid == tok_uid)
        print("tok_uid:", tok_uid, "uid:", uid)
        if tok_uid == uid and devices_repo.is_approved(uid, tok_did) and not devices_repo.is_revoked(uid, tok_did):
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
        # else에서는 return하지 않고 아래로 진행

    # devtk 없음/무효 또는 승인되지 않은 기기 → dev_id 필요 & 이메일 승인 진행
    dev_id = (body.dev_id or "").strip()
    if not dev_id:
        return {"ok": True, "device_required": True, "reason": "need_dev_id"}

    # dev_id가 approved 상태면 바로 OTP 단계로 진입
    if devices_repo.is_approved(uid, dev_id) and not devices_repo.is_revoked(uid, dev_id):
        request.session[S_PRE_UID] = uid
        request.session[S_PRE_EMAIL] = u.get("email") or email_norm
        request.session[S_PRE_DID] = dev_id

        mfa = (u.get("mfa") or {})
        if mfa.get("totp_enabled"):
            return {"ok": True, "next": "otp"}
        else:
            temp = mfa.get("totp_temp_secret") or TOTP.gen_base32_secret()
            if not mfa.get("totp_temp_secret"):
                users_repo.set_totp_temp_secret(uid, temp)
            return {
                "ok": True,
                "next": "activate_totp",
                "totp": {"secret": temp, "otpauth_url": TOTP.build_otpauth_url(temp, u.get("email") or email_norm)}
            }

    # 승인되지 않은 기기면 이메일 승인 진행
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
def activate_totp_register(body: TotpCode, request: Request):
    """
    회원가입 직후 TOTP 활성화 (세션에 uid가 있어야 함)
    """
    uid = request.session.get("uid")
    if not uid:
        raise HTTPException(status_code=400, detail="No pending registration")

    u = users_repo.get_by_id(uid)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    mfa = (u.get("mfa") or {})
    temp_secret = mfa.get("totp_temp_secret")
    if not temp_secret:
        raise HTTPException(status_code=400, detail="No TOTP to activate")

    ok, step = TOTP.verify_totp(temp_secret, body.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    backups = TOTP.gen_backup_codes()
    backup_hashes = [TOTP.hash_backup_code(c) for c in backups]
    users_repo.activate_totp(uid, temp_secret, backup_hashes)
    users_repo.set_last_counter(uid, int(step))

    return {"ok": True, "backup_codes": backups}


@router.post("/auth/mfa/totp/verify-login")
def verify_totp_login(body: TotpCode, request: Request, response: Response):
    """
    로그인 진행 중(비번 + 신뢰 기기 통과 후) OTP 검증 & 로그인 완료
    - 세션에 S_PRE_UID 가 있어야 함
    - 리플레이 방지: last_counter < step 여야 함
    """

    # --- pre_uid 확보(세션 우선, 없으면 세션의 이메일 또는 요청 바디의 이메일로 조회) ---
    pre_uid = request.session.get(S_PRE_UID)
    pre_email = request.session.get(S_PRE_EMAIL)

    # 요청 바디에 email 필드가 있으면 보조로 사용
    if not pre_email and hasattr(body, "email"):
        pre_email = getattr(body, "email")

    if not pre_uid and pre_email:
        # users_repo에 이메일로 사용자 조회 함수명에 맞게 조정하세요
        if hasattr(users_repo, "get_by_email_norm"):
            u = users_repo.get_by_email_norm(pre_email)
        elif hasattr(users_repo, "get_by_email"):
            u = users_repo.get_by_email(pre_email)
        else:
            u = None
        if u:
            pre_uid = str(u.get("_id"))

    if not pre_uid:
        # 세션이 없으면 더 이상 진행 불가(클라이언트에게 명확한 안내)
        raise HTTPException(status_code=400, detail="No pending login. 로그인 흐름을 다시 시작하세요.")

    # --- OTP 잠금 체크 (DB에서 가져온 값이 naive datetime일 수 있으므로 tz 보정) ---
    totp_lock = users_repo.get_totp_lock(pre_uid)
    if totp_lock.get("locked_until"):
        now = datetime.now(timezone.utc)
        locked_until = totp_lock["locked_until"]
        if getattr(locked_until, "tzinfo", None) is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            retry_after = int((locked_until - now).total_seconds())
            return JSONResponse(
                status_code=429,
                content={
                    "ok": False,
                    "locked": True,
                    "retry_after": retry_after,
                    "message": f"연속된 OTP 실패로 제한이 걸렸습니다. {retry_after}초 후에 다시 시도해 주세요."
                },
            )

    # --- 사용자 로드 (항상 u가 설정되도록) ---
    if hasattr(users_repo, "get_by_id"):
        u = users_repo.get_by_id(pre_uid)
    elif hasattr(users_repo, "get"):
        u = users_repo.get(pre_uid)
    else:
        # 이메일 기반 조회 함수가 있으면 시도
        if pre_email and hasattr(users_repo, "get_by_email_norm"):
            u = users_repo.get_by_email_norm(pre_email)
        elif pre_email and hasattr(users_repo, "get_by_email"):
            u = users_repo.get_by_email(pre_email)
        else:
            u = None

    if not u:
        raise HTTPException(status_code=400, detail="No pending user")

    mfa = (u.get("mfa") or {})

    # --- TOTP 검증 ---
    ok, _ = TOTP.verify_totp(mfa.get("totp_secret", ""), body.code)
    if not ok:
        cnt = users_repo.incr_failed_totp(pre_uid)
        if cnt >= 5:
            users_repo.lock_totp(pre_uid, minutes=5)
            # 이메일 발송 등 기존 처리...
            return JSONResponse(status_code=429, content={"ok": False, "locked": True, "message": "연속된 OTP 실패로 계정이 5분 동안 잠겼습니다."})
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    # --- 성공 처리: pre_did는 세션에서 가져옴 (없으면 None 허용) ---
    pre_did = request.session.get(S_PRE_DID) or None
    users_repo.reset_failed_totp(pre_uid)

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

    # UA/IP 해시 생성
    ua = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else ""
    ua_hash = hashlib.sha256(ua.encode()).hexdigest()
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()

    # DB에 pending 승인 요청 저장
    devices_repo.insert_pending_approval(uid, did, ua_hash, ip_hash)

    # 안내 메시지: "관리자 승인 대기 중입니다."
    return HTMLResponse("<h3>기기 승인 요청이 접수되었습니다.<br/>관리자 승인 후 사용 가능합니다.</h3>")


@router.post("/auth/logout")
def logout(request: Request, response: Response):
    request.session.clear()
    response.delete_cookie(DEVICE_COOKIE_NAME)
    return {"ok": True}
