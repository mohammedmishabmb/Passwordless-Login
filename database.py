import os
from datetime import datetime, timedelta, timezone

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
CHALLENGE_TTL_SECONDS = 60

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client[os.environ.get("MONGO_DB", "passwordless_auth")]
users = db["users"]
challenges = db["challenges"]


def init_database():
    client.admin.command("ping")
    users.create_index("username", unique=True)
    challenges.create_index("username", unique=True)
    # Mongo removes expired challenges automatically.
    challenges.create_index("expires_at", expireAfterSeconds=0)


def create_user(username, public_key):
    try:
        users.insert_one({"username": username, "public_key": public_key})
    except DuplicateKeyError:
        return False
    return True


def get_user(username):
    return users.find_one({"username": username})


def save_challenge(username, challenge):
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    challenges.update_one(
        {"username": username},
        {"$set": {"challenge": challenge, "expires_at": expires_at}},
        upsert=True,
    )


def consume_challenge(username):
    """Atomically fetch and delete the challenge so it can only be used once."""
    doc = challenges.find_one_and_delete({"username": username})
    if not doc:
        return None
    expires_at = doc["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return None
    return doc["challenge"]
