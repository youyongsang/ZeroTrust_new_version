# server/api/services/totp_service.py
"""
TOTP 생성/검증, QR(otpauth) URL, 백업코드 생성 유틸
RFC 6238 (HMAC-SHA1, 6 digits, 30s) 기본값
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import os
import time
from typing import Iterable, Optional, Tuple, List

from ..core.config import settings


# ===== 기본 파라미터 =====
TOTP_PERIOD = int(getattr(settings, "TOTP_PERIOD", 30))
TOTP_DIGITS = 6
TOTP_WINDOW = int(getattr(settings, "TOTP_WINDOW", 1))  # 허용 윈도우 ±1
TOTP_ISSUER = getattr(settings, "TOTP_ISSUER", "auth-min")

# 백업코드 개수/길이
BACKUP_COUNT = int(getattr(settings, "BACKUP_CODE_COUNT", 10))
BACKUP_LEN = int(getattr(settings, "BACKUP_CODE_LEN", 10))

# 해시 페퍼 (백업코드/내부 해싱에 사용)
_PEPPER = (
    getattr(settings, "SESSION_SECRET", None)
    or getattr(settings, "SECRET_KEY", None)
    or "pepper_change_me"
)


# ===== Secret / otpauth =====
def gen_base32_secret(nbytes: int = 20) -> str:
    return base64.b32encode(os.urandom(nbytes)).decode("ascii").rstrip("=")


def build_otpauth_url(secret_b32: str, account_name: str, issuer: str | None = None) -> str:
    issuer = issuer or TOTP_ISSUER
    label = f"{issuer}:{account_name}"
    # android/ms authenticator 호환
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret_b32}"
        f"&issuer={issuer}"
        f"&period={TOTP_PERIOD}"
        f"&digits={TOTP_DIGITS}"
        f"&algorithm=SHA1"
    )


# ===== HOTP/TOTP =====
def _int_to_bytes(i: int) -> bytes:
    return i.to_bytes(8, "big")


def _dynamic_truncation(h: bytes) -> int:
    offset = h[-1] & 0x0F
    code = ((h[offset] & 0x7F) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3]
    return code


def hotp(secret: bytes, counter: int, digits: int = TOTP_DIGITS) -> int:
    mac = hmac.new(secret, _int_to_bytes(counter), hashlib.sha1).digest()
    code = _dynamic_truncation(mac) % (10 ** digits)
    return code


def _b32_to_bytes(secret_b32: str) -> bytes:
    pad = "=" * (-len(secret_b32) % 8)
    return base64.b32decode(secret_b32 + pad, casefold=True)


def totp(secret_b32: str, for_time: Optional[int] = None, period: int = TOTP_PERIOD) -> Tuple[int, int]:
    """현재 코드와 counter(step) 반환"""
    ts = int(for_time or time.time())
    counter = ts // period
    code = hotp(_b32_to_bytes(secret_b32), counter, TOTP_DIGITS)
    return code, counter


def verify_totp(secret_b32: str, code_str: str, window: int = TOTP_WINDOW) -> Tuple[bool, Optional[int]]:
    """±window 내 허용. (ok, 사용된 counter)"""
    code_str = (code_str or "").strip()
    if not (code_str.isdigit() and len(code_str) == TOTP_DIGITS):
        return False, None

    now = int(time.time())
    for off in range(-window, window + 1):
        step = (now // TOTP_PERIOD) + off
        calc = hotp(_b32_to_bytes(secret_b32), step, TOTP_DIGITS)
        if f"{calc:0{TOTP_DIGITS}d}" == code_str:
            return True, step
    return False, None


# ===== 백업 코드 =====
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 보기 쉬운 문자셋

def gen_backup_codes(n: int = BACKUP_COUNT, length: int = BACKUP_LEN) -> List[str]:
    out = []
    for _ in range(n):
        b = os.urandom(length)
        out.append("".join(_ALPHABET[b[i] % len(_ALPHABET)] for i in range(length)))
    return out


def hash_backup_code(code: str) -> str:
    h = hashlib.sha256()
    h.update(_PEPPER.encode())
    h.update(code.encode())
    return f"sha256:{h.hexdigest()}"
