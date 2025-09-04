# server/api/db/users_repo.py
from typing import Optional
from bson import ObjectId
from datetime import datetime, timezone
from .mongo import users_col

def get_by_email_norm(email_norm: str) -> Optional[dict]:
    return users_col().find_one({"email_norm": email_norm})

def insert_user(email: str, email_norm: str, password_hash: str) -> str:
    doc = {
        "email": email,
        "email_norm": email_norm,
        "password_hash": password_hash,
        "email_verified": False,
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
