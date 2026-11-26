import re
import secrets
from typing import Tuple, Dict

import pyotp
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# CONSTANTES DE SEGURIDAD (SCRYPT)
SALT_LENGTH = 16       # 128 bits de aleatoriedad
KEY_LENGTH = 32        # 256 bits de salida
SCRYPT_N = 2**14       # Coste de CPU/Memoria (16384)
SCRYPT_R = 8           # Tamaño de bloque
SCRYPT_P = 1           # Paralelismo

# 1. VALIDACIÓN Y HASHING DE CONTRASEÑAS

# Comprueba que la contraseña sea robusta antes de registrarla: 
# Mínimo 8 caracteres
# Al menos una mayúscula, una minúscula, un número y un carácter especial
def validate_password_strength(password: str) -> Tuple[bool, str]:

    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña debe incluir al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return False, "La contraseña debe incluir al menos una letra minúscula."
    if not re.search(r"[0-9]", password):
        return False, "La contraseña debe incluir al menos un número."
    if not re.search(r"[^a-zA-Z0-9\s]", password):
        return False, "La contraseña debe incluir al menos un carácter especial (ej. !, @, #, $)."
    return True, "Contraseña robusta."

def hash_password(password: str) -> Tuple[str, str]:
    
    # Generamos un salt único de 16 bytes usando secrets (aleatoriedad criptográfica)
    # Así dos usuarios con la misma contraseña tendrán hashes completamente distintos
    salt = secrets.token_bytes(SALT_LENGTH)
    # Configuramos el motor Scrypt con el salt y los parámetros de coste definidos arriba
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    # Convertimos la contraseña a bytes (UTF-8) y calculamos su hash de 32 bytes
    password_hash = kdf.derive(password.encode("utf-8"))
    # Pasamos tanto el salt como el hash a texto hexadecimal para poder guardarlos en el JSON
    return salt.hex(), password_hash.hex()

# Verifica una contraseña contra su salt y hash almacenados usando
# comparación en tiempo constante (.verify).
def verify_password(password: str, salt_hex: str, stored_hash_hex: str) -> bool:

    try:
        # Reconvertimos el salt y el hash guardado de texto hexadecimal a bytes originales
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
        # Volvemos a instanciar Scrypt exactamente con el mismo salt y parámetros del registro
        kdf = Scrypt(
            salt=salt,
            length=KEY_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        )
        # Recalculamos el hash y lo comparamos en tiempo constante (evita ataques de temporización)
        # Si no coincide, Scrypt lanza automáticamente la excepción InvalidKey
        kdf.verify(password.encode("utf-8"), stored_hash)
        return True
    except (InvalidKey, ValueError):
        return False


# 2. SEGUNDO FACTOR DE AUTENTICACIÓN (TOTP)

def generate_totp_secret() -> str:
    # Crea una clave secreta aleatoria en formato Base32
    return pyotp.random_base32()


def get_current_totp_code(totp_secret: str) -> str:
    #Calcula el código temporal actual de 6 dígitos, instanciando al generador TOTP con la semilla del usuario
    totp = pyotp.TOTP(totp_secret)
    return totp.now()


def verify_totp(totp_secret: str, code: str) -> bool:
    # Verifica el código de 6 dígitos introducido por el usuario.
    # valid_window=1 permite un margen de +-30 segundos por desincronización de reloj.
    if not code or not code.isdigit():
        return False
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code, valid_window=1)


# 3. GENERACIÓN Y CUSTODIA DE CLAVES DE USUARIO

# Genera los dos pares de claves asimétricas para un usuario nuevo de CryptoPay:
# RSA-2048: para cifrado híbrido (recibir claves AES).
# ECDSA (curva SECP256R1 / P-256): para firmar digitalmente transferencias.
def generate_user_keypairs(password: str) -> Dict[str, str]:

    # Convertimos la contraseña a bytes y creamos el "candado" para cifrar las claves privadas
    # BestAvailableEncryption usa el cifrado simétrico más fuerte disponible en la librería
    password_bytes = password.encode("utf-8")
    encryption_algo = serialization.BestAvailableEncryption(password_bytes)

    # Par de claves RSA-2048

    # Generamos la clave privada RSA en memoria RAM (2048 bits, exponente estándar 65537)
    rsa_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Extraemos la clave pública, la empaquetamos en formato PEM (X.509) y la pasamos a texto str
    rsa_public_pem = rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    # Empaquetamos la clave privada en formato PKCS#8 PEM aplicando el candado (encryption_algo)
    # Así nunca se guarda la clave privada en claro en el JSON
    rsa_private_enc_pem = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    ).decode("utf-8")

    # Par de claves ECDSA (Curva NIST P-256)

    # Generamos la clave privada de curva elíptica usando la curva estándar SECP256R1 (256 bits)
    ecdsa_private = ec.generate_private_key(ec.SECP256R1())
    # Extraemos y serializamos la clave pública ECDSA en formato PEM legible para el JSON
    ecdsa_public_pem = ecdsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    # Serializamos y ciframos la clave privada ECDSA en PKCS#8 PEM con la misma contraseña del usuario
    ecdsa_private_enc_pem = ecdsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    ).decode("utf-8")
    
    # Devolvemos las 4 claves en texto listas para guardarse en cryptopay_data.json
    return {
        "rsa_public_pem": rsa_public_pem,
        "rsa_private_enc_pem": rsa_private_enc_pem,
        "ecdsa_public_pem": ecdsa_public_pem,
        "ecdsa_private_enc_pem": ecdsa_private_enc_pem
    }
