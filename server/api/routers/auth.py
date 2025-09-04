# server/api/routers/auth.py
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr
from fastapi.responses import HTMLResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from ..db import users_repo
from ..services.password import verify_password, hash_password
from ..services.email_service import send_email
from ..core.config import settings

router = APIRouter()

# ----- token signer for email verification -----
email_signer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="email-verify")

# ----- models -----
class LoginReq(BaseModel):
    email: str
    password: str

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
    # link handled by GET /auth/verify
    return f"{settings.SITE_BASE_URL}/auth/verify?token={token}"

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
def login(body: LoginReq, request: Request):
    email_norm = normalize_email(body.email)
    if not email_norm or not body.password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    u = users_repo.get_by_email_norm(email_norm)
    if not u or not verify_password(body.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not u.get("email_verified", False):
        raise HTTPException(status_code=403, detail="Email not verified")

    request.session.clear()
    request.session["uid"] = str(u["_id"])
    request.session["email"] = u.get("email") or email_norm
    return {"ok": True}

@router.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}
