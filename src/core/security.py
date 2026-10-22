import hashlib, secrets
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

_ph = PasswordHasher()
_DUMMY = _ph.hash("dummy-password-for-constant-time")

def hash_password(password: str) -> str:
    return _ph.hash(password)

def verify_password(password: str, password_hash: Optional[str]) -> bool:
    """With hash=None, burns equal time against a dummy hash (anti user-enumeration)."""
    try:
        _ph.verify(password_hash or _DUMMY, password)
        return password_hash is not None
    except (VerifyMismatchError, InvalidHashError):
        return False

def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
