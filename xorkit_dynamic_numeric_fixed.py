# xorkit_dynamic_numeric_fixed.py
import os, hmac, hashlib, random
from typing import Dict, Any

PBKDF2_ITERS = 200_000
MASTER_KEY_LEN = 32
FLUID_NUM_DIGITS = 12
DIVISION_DIGITS = 3
CHARSET = [chr(i) for i in range(32, 127)]  # printable ASCII

# ---------- Key derivation ----------
def derive_master_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERS, dklen=MASTER_KEY_LEN)

def derive_subkey(master: bytes, label: bytes) -> bytes:
    return hmac.new(master, label, hashlib.sha256).digest()

def drbg(subkey: bytes, label: bytes, counter: int, digits: int) -> str:
    msg = label + counter.to_bytes(4, 'big')
    out = hmac.new(subkey, msg, hashlib.sha256).digest()
    val = int.from_bytes(out, 'big') % (10**digits)
    return str(val).zfill(digits)

# ---------- Table generators ----------
def gen_fluid_table(sk: bytes) -> Dict[str, str]:
    table = {}
    for i, ch in enumerate(CHARSET):
        table[ch] = drbg(sk, b'fluid', i, FLUID_NUM_DIGITS)
    return table

def gen_number_div(sk: bytes) -> Dict[str, str]:
    table = {}
    for d in range(10):
        table[str(d)] = drbg(sk, b'div', d, DIVISION_DIGITS)
    return table

# ---------- Conversions ----------
def digits_to_bytes(digits: str) -> bytes:
    assert len(digits) % 3 == 0
    return bytes(int(digits[i:i+3]) % 256 for i in range(0, len(digits), 3))

def bytes_to_digits(b: bytes) -> str:
    return ''.join(f"{x:03d}" for x in b)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ---------- Encryption ----------
def encrypt_numeric(password: str, plaintext: str) -> Dict[str, Any]:
    salt = os.urandom(16)
    master = derive_master_key(password, salt)

    sk1 = derive_subkey(master, b"fluid")
    sk2 = derive_subkey(master, b"div")
    sk3 = derive_subkey(master, b"xor")

    Fluid = gen_fluid_table(sk1)
    Div = gen_number_div(sk2)

    concat = ''.join(Fluid[ch] for ch in plaintext if ch in Fluid)
    stage2 = ''.join(Div[d] for d in concat)

    stage2_bytes = digits_to_bytes(stage2)
    keystream = hashlib.sha256(sk3 + salt).digest()
    cipher_bytes = xor_bytes(stage2_bytes, keystream * (len(stage2_bytes)//len(keystream)+1))
    cipher_digits = bytes_to_digits(cipher_bytes)

    tag = hashlib.sha256(master + cipher_digits.encode()).hexdigest()
    return {"cipher": cipher_digits, "salt": salt.hex(), "tag": tag, "meta": {"f": FLUID_NUM_DIGITS, "d": DIVISION_DIGITS}}

# ---------- Decryption ----------
def decrypt_numeric(password: str, env: Dict[str, Any]) -> str:
    salt = bytes.fromhex(env["salt"])
    cipher_digits = env["cipher"]

    master = derive_master_key(password, salt)
    sk1 = derive_subkey(master, b"fluid")
    sk2 = derive_subkey(master, b"div")
    sk3 = derive_subkey(master, b"xor")

    Fluid = gen_fluid_table(sk1)
    Div = gen_number_div(sk2)
    inv_Div = {v: k for k, v in Div.items()}
    inv_Fluid = {v: k for k, v in Fluid.items()}

    cipher_bytes = digits_to_bytes(cipher_digits)
    keystream = hashlib.sha256(sk3 + salt).digest()
    stage2_bytes = xor_bytes(cipher_bytes, keystream * (len(cipher_bytes)//len(keystream)+1))
    stage2_digits = bytes_to_digits(stage2_bytes)

    # Invert DIV stage
    num_seq = []
    for i in range(0, len(stage2_digits), DIVISION_DIGITS):
        piece = stage2_digits[i:i+DIVISION_DIGITS]
        if piece in inv_Div:
            num_seq.append(inv_Div[piece])
    concat = ''.join(num_seq)

    # Invert Fluid stage
    chars = []
    for i in range(0, len(concat), FLUID_NUM_DIGITS):
        piece = concat[i:i+FLUID_NUM_DIGITS]
        if piece in inv_Fluid:
            chars.append(inv_Fluid[piece])
    return ''.join(chars)
