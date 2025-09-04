# server/scripts/seed_user.py
import argparse
from api.db.mongo import users_col
from api.services.password import hash_password

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    email = args.email.strip()
    email_norm = normalize_email(email)

    col = users_col()
    if col.find_one({"email_norm": email_norm}):
        print(f"[skip] already exists: {email_norm}")
        return

    pw_hash = hash_password(args.password)
    col.insert_one({
        "email": email,
        "email_norm": email_norm,
        "password_hash": pw_hash
    })
    print(f"[ok] inserted: {email_norm}")

if __name__ == "__main__":
    main()
