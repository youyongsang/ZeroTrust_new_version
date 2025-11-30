# server/api/services/password.py
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher(time_cost=3, memory_cost=64*1024, parallelism=2)

def hash_password(pw: str) -> str:
    return _ph.hash(pw)

def verify_password(pw: str, hashed: str) -> bool:
    try:
        _ph.verify(hashed, pw)
        return True
    except VerifyMismatchError:
        return False

# 편의: 해시 생성 CLI
if __name__ == "__main__":
    import getpass
    p = getpass.getpass("Password to hash: ")
    print(hash_password(p))
