# server/api/db/devices_repo.py
from datetime import datetime, timezone
from typing import Optional
from bson import ObjectId
from .mongo import users_col, _db

# 별도 컬렉션 생성
_devices = _db["devices"]
_devices.create_index([("user_id", 1), ("device_id", 1)], unique=True)

def upsert_device(user_id: str, device_id: str, label: str | None, ua_hash: str | None, ip_hash: str | None):
    _devices.update_one(
        {"user_id": user_id, "device_id": device_id},
        {"$set": {
            "user_id": user_id,
            "device_id": device_id,
            "label": label,
            "ua_hash": ua_hash,
            "ip_hash": ip_hash,
            "revoked": False,
            "lastSeenAt": datetime.now(timezone.utc),
            "updatedAt": datetime.now(timezone.utc),
        }, "$setOnInsert": {
            "createdAt": datetime.now(timezone.utc),
        }},
        upsert=True
    )

def mark_seen(user_id: str, device_id: str):
    _devices.update_one(
        {"user_id": user_id, "device_id": device_id, "revoked": {"$ne": True}},
        {"$set": {"lastSeenAt": datetime.now(timezone.utc), "updatedAt": datetime.now(timezone.utc)}}
    )

def is_revoked(user_id: str, device_id: str) -> bool:
    row = _devices.find_one({"user_id": user_id, "device_id": device_id})
    return bool(row and row.get("revoked"))

def revoke_device(user_id: str, device_id: str) -> bool:
    res = _devices.update_one(
        {"user_id": user_id, "device_id": device_id},
        {"$set": {"revoked": True, "updatedAt": datetime.now(timezone.utc)}}
    )
    return res.modified_count > 0

def insert_pending_approval(user_id: str, device_id: str, ua_hash: str, ip_hash: str):
    _devices.update_one(
        {"user_id": user_id, "device_id": device_id},
        {"$set": {
            "user_id": user_id,
            "device_id": device_id,
            "ua_hash": ua_hash,
            "ip_hash": ip_hash,
            "status": "pending",
            "requestedAt": datetime.now(timezone.utc),
            "revoked": False,
        }, "$setOnInsert": {
            "createdAt": datetime.now(timezone.utc),
        }},
        upsert=True
    )

def get_pending_approvals():
    return list(_devices.find({"status": "pending"}))

def approve_device(user_id: str, device_id: str):
    _devices.update_one(
        {"user_id": user_id, "device_id": device_id, "status": "pending"},
        {"$set": {
            "status": "approved",
            "approvedAt": datetime.now(timezone.utc),
            "revoked": False,
            "updatedAt": datetime.now(timezone.utc),
        }}
    )

def is_approved(user_id: str, device_id: str) -> bool:
    doc = _devices.find_one({"user_id": user_id, "device_id": device_id, "status": "approved"})
    return bool(doc)
