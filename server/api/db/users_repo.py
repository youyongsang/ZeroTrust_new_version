# server/api/db/users_repo.py
from __future__ import annotations

from typing import Optional, List, Tuple
from bson import ObjectId
from datetime import datetime, timezone
import hashlib
import secrets

from .mongo import users_col


# ---- 공통 유틸 ----
def _utcnow():
    return datetime.now(timezone.utc)


# ---- 조회 계열 ----
def get_by_email_norm(email_norm: str) -> Optional[dict]:
    """정규화된 이메일로 사용자 1명 조회"""
    return users_col().find_one({"email_norm": email_norm})


def get_by_id(user_id: str) -> Optional[dict]:
    """문자열 id(ObjectId)로 사용자 1명 조회"""
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return users_col().find_one({"_id": oid})


def to_public_user(u: dict) -> dict:
    """프론트로 넘길 공개 사용자 형태"""
    return {"id": str(u["_id"]), "email": u.get("email")}


# ---- 생성/수정 계열 (기본 회원가입; 링크/코드 방식에서 공용으로 사용 가능) ----
def insert_user(email: str, email_norm: str, password_hash: str) -> str:
    """
    이메일만 검증/저장하는 베이직 가입(이메일 인증 미완료).
    OTP 강제 가입 흐름이 아니라면 남겨둡니다.
    """
    doc = {
        "email": email,
        "email_norm": email_norm,
        "password_hash": password_hash,
        "email_verified": False,
        "createdAt": _utcnow(),
        "updatedAt": _utcnow(),
    }
    res = users_col().insert_one(doc)
    return str(res.inserted_id)


def insert_user_with_mfa(
    email: str,
    email_norm: str,
    pw_hash: str,
    totp_secret: str,
    backup_hashes: List[str],
) -> ObjectId:
    """
    이메일 코드 + 첫 OTP 검증에 성공한 시점에 최종 사용자 문서를 생성.
    - email_verified: True
    - MFA(TOTP) 활성 상태로 저장
    """
    doc = {
        "email": email,
        "email_norm": email_norm,
        "email_verified": True,
        "password_hash": pw_hash,
        "mfa": {
            "totp_enabled": True,
            "totp_secret": totp_secret,
            "backup_hashes": backup_hashes,
        },
        "createdAt": _utcnow(),
        "updatedAt": _utcnow(),
    }
    res = users_col().insert_one(doc)
    return res.inserted_id


def set_email_verified(email_norm: str) -> bool:
    """이메일 인증 완료 처리(링크 방식 사용 시)"""
    res = users_col().update_one(
        {"email_norm": email_norm},
        {"$set": {"email_verified": True, "updatedAt": _utcnow()}},
    )
    return res.modified_count > 0


# ---- MFA(TOTP) 관련 (운영/관리용) ----
def set_totp_temp_secret(user_id: str, temp_secret: str) -> bool:
    """
    (선택) 기존 흐름 호환: 로그인 상태에서 OTP 등록 시작 시 임시 시크릿을 DB에 저장.
    새 가입 플로우(세션 보관)에서는 사용하지 않아도 됨.
    """
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "mfa.totp_temp_secret": temp_secret,
                "updatedAt": _utcnow(),
            }
        },
    )
    return res.modified_count > 0


def activate_totp(user_id: str, secret: str, backup_hashes: List[str]) -> bool:
    """
    (선택) 기존 흐름 호환: 임시 시크릿 → 정식 활성화로 전환.
    새 가입 플로우에선 insert_user_with_mfa를 사용하므로
    운영상 재등록/교체 등에서만 필요할 수 있음.
    """
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "mfa.totp_enabled": True,
                "mfa.totp_secret": secret,
                "mfa.backup_hashes": backup_hashes,
                "updatedAt": _utcnow(),
            },
            "$unset": {"mfa.totp_temp_secret": ""},
        },
    )
    return res.modified_count > 0


def disable_totp(user_id: str) -> bool:
    """
    TOTP 비활성화(운영 도구/사용자 요청 등).
    """
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {
            "$unset": {
                "mfa.totp_secret": "",
                "mfa.totp_temp_secret": "",
                "mfa.backup_hashes": "",
            },
            "$set": {"mfa.totp_enabled": False, "updatedAt": _utcnow()},
        },
    )
    return res.modified_count > 0


def consume_backup_code(user_id: str, code_hash: str) -> bool:
    """
    사용된 백업코드 제거(로그인 성공 시 호출).
    """
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {
            "$pull": {"mfa.backup_hashes": code_hash},
            "$set": {"updatedAt": _utcnow()},
        },
    )
    return res.modified_count > 0


# ---- 백업코드 유틸 ----
def _hash_backup_code_raw(code: str, pepper: str) -> str:
    """백업코드 + pepper → sha256 해시"""
    return hashlib.sha256((code + pepper).encode("utf-8")).hexdigest()


def generate_backup_codes(count: int, pepper: str) -> Tuple[List[str], List[str]]:
    """
    백업코드 평문/해시 세트를 생성.
    - 반환: (plain_list, hash_list)
    - DB에는 hash_list만 저장하세요.
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 혼동되는 문자(O,0,I,1 등) 제외
    plains: List[str] = []
    hashes: List[str] = []
    for _ in range(count):
        code = "".join(secrets.choice(alphabet) for _ in range(10))
        plains.append(code)
        hashes.append(_hash_backup_code_raw(code, pepper))
    return plains, hashes
