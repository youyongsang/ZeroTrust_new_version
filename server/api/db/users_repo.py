# server/api/db/users_repo.py
from __future__ import annotations
from typing import Optional, List, Dict, Any
from bson import ObjectId
from datetime import datetime, timezone, timedelta
from pymongo import ReturnDocument
from .mongo import users_col

# ===== 기본 조회/삽입 =====
def get_by_email_norm(email_norm: str) -> Optional[dict]:
    return users_col().find_one({"email_norm": email_norm})

def get_by_id(user_id: str) -> Optional[dict]:
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return users_col().find_one({"_id": oid})

def insert_user(email: str, email_norm: str, password_hash: str) -> str:
    doc: Dict[str, Any] = {
        "email": email,
        "email_norm": email_norm,
        "password_hash": password_hash,
        "email_verified": False,
        # 이메일 코드(6자리) 검증용 메타
        # "email_code": {
        #   "hash": "...",           # sha256:...
        #   "expiresAt": datetime,
        #   "attempts": 0,
        # }
        "mfa": {
            "totp_enabled": False,
            # "totp_temp_secret": "...",  # 최초 등록 때 임시로 저장
            # "totp_secret": "...",       # 활성화 후 저장
            # "backup_hashes": [...],
            # "last_counter": 0,
        },
        "createdAt": datetime.now(timezone.utc),
        "updatedAt": datetime.now(timezone.utc),
    }
    res = users_col().insert_one(doc)
    return str(res.inserted_id)

def set_email_verified(email_norm: str) -> bool:
    res = users_col().update_one(
        {"email_norm": email_norm},
        {"$set": {"email_verified": True, "updatedAt": datetime.now(timezone.utc)}}
    )
    return res.modified_count > 0

def to_public_user(u: dict) -> dict:
    return {"id": str(u["_id"]), "email": u.get("email")}

# ===== 이메일 코드 관리 =====
def set_email_code(email_norm: str, code_hash: str, expires_at: datetime) -> bool:
    res = users_col().update_one(
        {"email_norm": email_norm},
        {"$set": {
            "email_code.hash": code_hash,
            "email_code.expiresAt": expires_at,
            "email_code.attempts": 0,
            "updatedAt": datetime.now(timezone.utc),
        }}
    )
    return res.modified_count > 0

def inc_email_code_attempt(email_norm: str) -> None:
    users_col().update_one(
        {"email_norm": email_norm},
        {"$inc": {"email_code.attempts": 1}, "$set": {"updatedAt": datetime.now(timezone.utc)}}
    )

def clear_email_code(email_norm: str) -> None:
    users_col().update_one(
        {"email_norm": email_norm},
        {"$unset": {"email_code": ""}, "$set": {"updatedAt": datetime.now(timezone.utc)}}
    )

# ===== TOTP / MFA =====
def set_totp_temp_secret(user_id: str, temp_secret: str) -> bool:
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"mfa.totp_temp_secret": temp_secret, "updatedAt": datetime.now(timezone.utc)}},
    )
    return res.modified_count > 0

def activate_totp(user_id: str, secret: str, backup_hashes: List[str]) -> bool:
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "mfa.totp_enabled": True,
                "mfa.totp_secret": secret,
                "mfa.backup_hashes": backup_hashes,
                "mfa.last_counter": 0,
                "updatedAt": datetime.now(timezone.utc),
            },
            "$unset": {"mfa.totp_temp_secret": ""},
        },
    )
    return res.modified_count > 0

def disable_totp(user_id: str) -> bool:
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {
            "$unset": {
                "mfa.totp_secret": "",
                "mfa.totp_temp_secret": "",
                "mfa.backup_hashes": ""
            },
            "$set": {"mfa.totp_enabled": False, "updatedAt": datetime.now(timezone.utc)},
        },
    )
    return res.modified_count > 0

def consume_backup_code(user_id: str, code_hash: str) -> bool:
    res = users_col().update_one(
        {"_id": ObjectId(user_id)},
        {"$pull": {"mfa.backup_hashes": code_hash}, "$set": {"updatedAt": datetime.now(timezone.utc)}},
    )
    return res.modified_count > 0

def get_last_counter(user_id: str) -> int:
    u = get_by_id(user_id)
    return int(((u or {}).get("mfa") or {}).get("last_counter") or 0)

def set_last_counter(user_id: str, counter: int) -> None:
    users_col().update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"mfa.last_counter": int(counter), "updatedAt": datetime.now(timezone.utc)}},
    )

    # ===== 로그인 실패 관리 ===== 

def incr_failed_login(user_id: str) -> int:
    now = datetime.now(timezone.utc)
    res = users_col().find_one_and_update(
        {"_id": ObjectId(user_id)},
        {"$inc": {"login_failed_count": 1}, "$set": {"login_last_failed_at": now}},
        return_document=ReturnDocument.AFTER,
    )
    return int(res.get("login_failed_count", 0))

def reset_failed_login(user_id: str) -> None:
    users_col().update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"login_failed_count": 0, "login_last_failed_at": None, "login_locked_until": None}},
    )

def lock_account(user_id: str, minutes: int = 5) -> None:
    locked_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    users_col().update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"login_locked_until": locked_until, "login_failed_count": 0, "login_last_failed_at": None}},
    )

def get_login_lock(user_id: str) -> dict:
    doc = users_col().find_one({"_id": ObjectId(user_id)}, {"login_failed_count": 1, "login_last_failed_at": 1, "login_locked_until": 1})
    if not doc:
        return {"count": 0, "last": None, "locked_until": None}
    return {"count": int(doc.get("login_failed_count", 0)), "last": doc.get("login_last_failed_at"), "locked_until": doc.get("login_locked_until")}

# ===== otp 로그인 실패 관리 =====

def incr_failed_totp(user_id: str) -> int:
    now = datetime.now(timezone.utc)
    res = users_col().find_one_and_update(
        {"_id": ObjectId(user_id)},
        {"$inc": {"totp_failed_count": 1}, "$set": {"totp_last_failed_at": now}},
        return_document=ReturnDocument.AFTER,
    )
    return int(res.get("totp_failed_count", 0))

def reset_failed_totp(user_id: str) -> None:
    users_col().update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"totp_failed_count": 0, "totp_last_failed_at": None, "totp_locked_until": None}},
    )

def lock_totp(user_id: str, minutes: int = 5) -> None:
    locked_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    users_col().update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"totp_locked_until": locked_until, "totp_failed_count": 0, "totp_last_failed_at": None}},
    )

def get_totp_lock(user_id: str) -> dict:
    doc = users_col().find_one({"_id": ObjectId(user_id)}, {"totp_failed_count": 1, "totp_last_failed_at": 1, "totp_locked_until": 1})
    if not doc:
        return {"count": 0, "last": None, "locked_until": None}
    return {"count": int(doc.get("totp_failed_count", 0)), "last": doc.get("totp_last_failed_at"), "locked_until": doc.get("totp_locked_until")}
