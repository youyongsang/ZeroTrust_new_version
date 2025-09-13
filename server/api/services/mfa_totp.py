# server/api/services/mfa_totp.py
import hashlib, secrets
import pyotp
from ..core.config import settings

def new_totp_secret() -> str:
    # Base32 160-bit secret
    return pyotp.random_base32()

def provisioning_uri(secret: str, email: str) -> str:
    # otpauth:// URI (앱에서 스캔/직접 입력 가능)
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=settings.ISSUER_NAME)

def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    # 시계 드리프트 허용(앞뒤 1윈도우)
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=valid_window)
    except Exception:
        return False

def generate_backup_codes(n: int) -> tuple[list[str], list[str]]:
    """평문 코드 리스트, sha256 해시 리스트(pepper 포함)를 함께 반환"""
    plain = []
    hashed = []
    for _ in range(max(1, n)):
        # 10자리 영숫자 코드(사람이 입력하기 쉬운 형태)
        code = secrets.token_hex(5)[:10]
        plain.append(code)
        h = hashlib.sha256((code + settings.BACKUP_CODE_PEPPER).encode("utf-8")).hexdigest()
        hashed.append(h)
    return plain, hashed

def hash_backup(code: str) -> str:
    return hashlib.sha256((code.strip() + settings.BACKUP_CODE_PEPPER).encode("utf-8")).hexdigest()
