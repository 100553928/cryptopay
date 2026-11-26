import secrets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# CONSTANTES DE SEGURIDAD (HMAC / HKDF)
HMAC_KEY_LENGTH = 32      # 256 bits (SHA-256)
TX_NONCE_BYTES = 16       # 128 bits de aleatoriedad para anti-replay
HKDF_INFO = b"cryptopay-settlement-hmac-v1"

# 1. DERIVACIÓN DE CLAVE Y NONCE ANTI-REPLAY

# Deriva una clave simétrica de 256 bits específica para HMAC-SHA256
# utilizando HKDF-SHA256.
def derive_hmac_key(master_secret: bytes, salt: bytes = None) -> bytes:
    
    # Configuramos la instancia HKDF usando SHA-256
    # El parámetro info asegura que la clave generada sirva exclusivamente para HMAC de liquidación
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HMAC_KEY_LENGTH,
        salt=salt,
        info=HKDF_INFO,
    )
    # Derivamos y devolvemos la clave simétrica final de 32 bytes a partir del secreto maestro
    return hkdf.derive(master_secret)


def generate_tx_nonce() -> str:
    # Genera un nonce criptográficamente seguro de 128 bits (en hexadecimal)
    # para identificar de forma única cada transferencia y evitar ataques
    # de repetición (Replay Attacks).
    return secrets.token_hex(TX_NONCE_BYTES)


# 2. CONSTRUCCIÓN DEL MENSAJE

def _build_settlement_payload(tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    tx_nonce: str
) -> bytes:
    
    # Unimos todos los datos contables con '|' en un orden fijo y forzando siempre 2 decimales en el importe
    canonical_str = f"{tx_id}|{sender}|{receiver}|{float(amount):.2f}|{tx_nonce}"
    # Convertimos la cadena a bytes UTF-8, que es el formato que exige la librería cryptography
    return canonical_str.encode("utf-8")


# 3. GENERACIÓN Y VERIFICACIÓN DE HMAC-SHA256

# Calcula la etiqueta HMAC-SHA256 sobre los datos de liquidación de la
# transferencia y la devuelve en hexadecimal para guardarla en el JSON.
def generate_settlement_hmac(
    hmac_key: bytes,
    tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    tx_nonce: str
) -> str:
    
    # Preparamos el bloque exacto de bytes con los datos contables de la transferencia
    payload = _build_settlement_payload(tx_id, sender, receiver, amount, tx_nonce)
    # Instanciamos el motor HMAC con nuestra clave secreta de 256 bits y el algoritmo SHA-256
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    # Introducimos los datos de la transferencia en el motor HMAC
    h.update(payload)
    # Cerramos el cálculo y obtenemos la etiqueta de 32 bytes
    tag = h.finalize()
    
    return tag.hex()

# Verifica en tiempo constante que la etiqueta HMAC-SHA256 coincide con
# los datos de la transferencia. Devuelve False si algún dato o la propia
# etiqueta han sido manipulados.
def verify_settlement_hmac(
    hmac_key: bytes,
    tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    tx_nonce: str,
    expected_hmac_hex: str
) -> bool:

    try:
        # Convertimos la etiqueta HMAC guardada en el JSON de texto hexadecimal a bytes
        expected_tag = bytes.fromhex(expected_hmac_hex)

        payload = _build_settlement_payload(tx_id, sender, receiver, amount, tx_nonce)
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(payload)

        # Comparamos en tiempo constante el HMAC recién calculado con expected_tag (evita Timing Attacks)
        # Si algún dato o la etiqueta fueron alterados, lanza automáticamente InvalidSignature
        h.verify(expected_tag)
        return True
    except (InvalidSignature, ValueError):
        return False
