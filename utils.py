# utils.py
import hashlib
import base64

# لایه رمزنگاری ساده‌شده
def onion_encrypt(data: bytes, layers: int = 3) -> bytes:
    for i in range(layers):
        data = base64.b64encode(data[::-1])
    return data

def onion_decrypt(data: bytes, layers: int = 3) -> bytes:
    for i in range(layers):
        data = base64.b64decode(data)[::-1]
    return data

# تابع checksum
def calculate_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
