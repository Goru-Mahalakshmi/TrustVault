import base64, hashlib, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.core.config import settings

def _master() -> bytes:
    if settings.MASTER_KEY_B64:
        key = base64.b64decode(settings.MASTER_KEY_B64)
        if len(key) != 32:
            raise RuntimeError("MASTER_KEY_B64 must decode to 32 bytes")
        return key
    if settings.ENVIRONMENT == "production":
        raise RuntimeError("MASTER_KEY_B64 is required in production")
    return hashlib.sha256(b"trustvault-dev-master-key").digest()

def _aad(doc_id, ver_id) -> bytes:
    return f"{doc_id}:{ver_id}".encode()

def storage_path(doc_id, ver_id) -> str:
    return os.path.join(settings.STORAGE_DIR, f"{doc_id}_{ver_id}.enc")   # never the user's filename

def encrypt_file(plain: bytes, doc_id, ver_id) -> dict:
    """Ephemeral 256-bit DEK per version; DEK wrapped by the master key. AAD binds ciphertext to its row."""
    dek, fnonce, dnonce = AESGCM.generate_key(256), os.urandom(12), os.urandom(12)
    aad = _aad(doc_id, ver_id)
    return {
        "ciphertext": AESGCM(dek).encrypt(fnonce, plain, aad),          # GCM tag is the last 16 bytes
        "file_nonce": base64.b64encode(fnonce).decode(),
        "dek_nonce": base64.b64encode(dnonce).decode(),
        "encrypted_dek": base64.b64encode(AESGCM(_master()).encrypt(dnonce, dek, aad)).decode(),
        "sha256_hash": hashlib.sha256(plain).hexdigest(),
    }

def decrypt_file(ciphertext: bytes, ver, doc_id) -> bytes:
    aad = _aad(doc_id, ver.id)
    dek = AESGCM(_master()).decrypt(base64.b64decode(ver.dek_nonce), base64.b64decode(ver.encrypted_dek), aad)
    return AESGCM(dek).decrypt(base64.b64decode(ver.file_nonce), ciphertext, aad)

def write_blob(path: str, data: bytes):
    os.makedirs(settings.STORAGE_DIR, exist_ok=True)
    with open(path, "xb") as f:
        f.write(data)
