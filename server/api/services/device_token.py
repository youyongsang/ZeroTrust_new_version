# server/api/services/device_token.py
"""
Device-token helper (no DB dependency)
- Make/verify a signed device token using itsdangerous.
- Contract matches routers/auth.py:
    make_device_token(uid, did) -> str
    verify_device_token(token)  -> dict {"uid":..., "did":...} | None
"""

from typing import Optional, Dict, Tuple
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from ..core.config import settings

# ===== Config =====
# Secret priority: SESSION_SECRET -> SECRET_KEY -> fallback
_SECRET = (
    getattr(settings, "SESSION_SECRET", None)
    or getattr(settings, "SECRET_KEY", None)
    or "change_me_device_secret"
)

# Use a dedicated salt for cookie tokens (different from email/device-approve links)
_SALT = "device-cookie"

# Default max age (days) for device cookie tokens
_DEVICE_TOKEN_EXPIRE_DAYS = getattr(settings, "DEVICE_TOKEN_EXPIRE_DAYS", 180)

# Cookie name must match routers/auth.py default ("devtk")
_DEVICE_COOKIE_NAME = getattr(settings, "DEVICE_COOKIE_NAME", "devtk")

# SameSite/Secure should follow the server's cookie policy
_COOKIE_SECURE = bool(getattr(settings, "COOKIE_SECURE", False))
_COOKIE_SAMESITE = getattr(settings, "COOKIE_SAMESITE", "lax")

# Signer
_SIGNER = URLSafeTimedSerializer(_SECRET, salt=_SALT)


def get_device_cookie_name() -> str:
    """Expose cookie name for reuse (optional)."""
    return _DEVICE_COOKIE_NAME


def make_device_token(user_id: str, device_id: str) -> str:
    """Create signed device token for cookie."""
    payload = {"uid": str(user_id), "did": str(device_id)}
    return _SIGNER.dumps(payload)


def verify_device_token(token: str, max_age_days: Optional[int] = None) -> Optional[Tuple[str, str]]:
    """
    Verify device token signature & expiration.
    Return (uid, did) on success; None on any failure.
    """
    if not token:
        return None
    max_age_days = max_age_days or _DEVICE_TOKEN_EXPIRE_DAYS
    try:
        data = _SIGNER.loads(token, max_age=max_age_days * 24 * 60 * 60)
        if not isinstance(data, dict):
            return None
        uid = data.get("uid")
        did = data.get("did")
        if not uid or not did:
            return None
        return (str(uid), str(did))
    except (BadSignature, SignatureExpired):
        return None
    except Exception:
        # Any unexpected parsing error: never raise to avoid 500s in /auth/login
        return None


def read_device_token_from_request(request) -> Optional[str]:
    """Convenience: read device token from FastAPI Request cookies."""
    try:
        return request.cookies.get(_DEVICE_COOKIE_NAME)
    except Exception:
        return None


def set_device_cookie_on_response(response, token: str, max_age_days: Optional[int] = None) -> None:
    """Set device token cookie on Response."""
    max_age_days = max_age_days or _DEVICE_TOKEN_EXPIRE_DAYS
    response.set_cookie(
        key=_DEVICE_COOKIE_NAME,
        value=token,
        max_age=max_age_days * 24 * 60 * 60,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        path="/",
    )
