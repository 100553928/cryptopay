import re
import secrets
from typing import Tuple, Dict

import pyotp
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ==========================================
# CONSTANTES DE SEGURIDAD (SCRYPT)
# ==========================================
SALT_LENGTH = 16       # 128 bits de aleatoriedad
KEY_LENGTH = 32        # 256 bits de salida
SCRYPT_N = 2**14       # Coste de CPU/Memoria (16384)
SCRYPT_R = 8           # Tamaño de bloque
SCRYPT_P = 1           # Paralelismo


# ==========================================
# 1. VALIDACIÓN Y HASHING DE CONTRASEÑAS
# ==========================================

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Comprueba que la contraseña sea robusta antes de registrarla:
    - Mínimo 8 caracteres
    - Al menos una mayúscula, una minúscula y un número
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña debe incluir al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return False, "La contraseña debe incluir al menos una letra minúscula."
    if not re.search(r"[0-9]", password):
        return False, "La contraseña debe incluir al menos un número."
    return True, "Contraseña robusta."


def hash_password(password: str) -> Tuple[str, str]:
    """
    Genera un salt aleatorio criptográficamente seguro y deriva el hash
    de la contraseña usando Scrypt.
    Devuelve (salt_hex, hash_hex) listos para guardar en JSON.
    """
    salt = secrets.token_bytes(SALT_LENGTH)
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    password_hash = kdf.derive(password.encode("utf-8"))
    return salt.hex(), password_hash.hex()


def verify_password(password: str, salt_hex: str, stored_hash_hex: str) -> bool:
    """
    Verifica una contraseña contra su salt y hash almacenados usando
    comparación en tiempo constante (Scrypt.verify).
    """
    try:
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
        kdf = Scrypt(
            salt=salt,
            length=KEY_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        )
        kdf.verify(password.encode("utf-8"), stored_hash)
        return True
    except (InvalidKey, ValueError):
        return False


# ==========================================
# 2. SEGUNDO FACTOR DE AUTENTICACIÓN (TOTP)
# ==========================================

def generate_totp_secret() -> str:
    """Genera una semilla secreta en Base32 para autenticación 2FA (RFC 6238)."""
    return pyotp.random_base32()


def get_current_totp_code(totp_secret: str) -> str:
    """Calcula el código temporal actual de 6 dígitos (útil para pruebas/interfaz)."""
    totp = pyotp.TOTP(totp_secret)
    return totp.now()


def verify_totp(totp_secret: str, code: str) -> bool:
    """
    Verifica el código de 6 dígitos introducido por el usuario.
    valid_window=1 permite un margen de +-30 segundos por desincronización de reloj.
    """
    if not code or not code.isdigit():
        return False
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code, valid_window=1)


# ==========================================
# 3. GENERACIÓN Y CUSTODIA DE CLAVES DE USUARIO
# ==========================================

def generate_user_keypairs(password: str) -> Dict[str, str]:
    """
    Genera los dos pares de claves asimétricas para un usuario nuevo de CryptoPay:
    - RSA-2048: para cifrado híbrido (recibir claves AES).
    - ECDSA (curva SECP256R1 / P-256): para firmar digitalmente transferencias.

    Las claves privadas se serializan en formato PKCS#8 PEM cifradas con la
    contraseña del usuario (BestAvailableEncryption).
    """
    password_bytes = password.encode("utf-8")
    encryption_algo = serialization.BestAvailableEncryption(password_bytes)

    # --- A) Par de claves RSA-2048 ---
    rsa_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    rsa_public_pem = rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    rsa_private_enc_pem = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    ).decode("utf-8")

    # --- B) Par de claves ECDSA (Curva NIST P-256) ---
    ecdsa_private = ec.generate_private_key(ec.SECP256R1())
    ecdsa_public_pem = ecdsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    ecdsa_private_enc_pem = ecdsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    ).decode("utf-8")

    return {
        "rsa_public_pem": rsa_public_pem,
        "rsa_private_enc_pem": rsa_private_enc_pem,
        "ecdsa_public_pem": ecdsa_public_pem,
        "ecdsa_private_enc_pem": ecdsa_private_enc_pem
    }


# Prueba rápida local de este bloque
if __name__ == "__main__":
    pwd = "MiPassword2026"
    ok, msg = validate_password_strength(pwd)
    print(f"[1] Validación: {ok} ({msg})")

    salt_h, hash_h = hash_password(pwd)
    print(f"[2] Salt (16B hex): {salt_h}")
    print(f"    Hash Scrypt:    {hash_h[:32]}...")
    print(f"    Verify OK:      {verify_password(pwd, salt_h, hash_h)}")
    print(f"    Verify Mal:     {verify_password('OtraClave123', salt_h, hash_h)}")

    totp_sec = generate_totp_secret()
    codigo = get_current_totp_code(totp_sec)
    print(f"[3] TOTP código actual: {codigo} | Válido: {verify_totp(totp_sec, codigo)}")

    claves = generate_user_keypairs(pwd)
    print(f"[4] Claves generadas -> RSA Privada cifrada empieza por:\n    {claves['rsa_private_enc_pem'].splitlines()[0]}")