# server/api/db/mongo.py
from pymongo import MongoClient, ASCENDING
from pymongo.errors import CollectionInvalid
from ..core.config import settings

_client = MongoClient(settings.MONGO_URI)
_db = _client[settings.DB_NAME]

def _ensure_initialized():
    # DB가 없으면 create_collection 호출로 컬렉션 만들고, 인덱스까지 준비
    try:
        if "users" not in _db.list_collection_names():
            _db.create_collection("users")
    except CollectionInvalid:
        pass  # 이미 있으면 무시

    coll = _db["users"]
    # 이메일 정규화 필드에 유니크 인덱스(없으면 생성, 있으면 그대로)
    coll.create_index([("email_norm", ASCENDING)], unique=True)
    return coll

_users = _ensure_initialized()

def users_col():
    return _users
