import secrets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ==========================================
# CONSTANTES DE SEGURIDAD (HMAC / HKDF)
# ==========================================
HMAC_KEY_LENGTH = 32      # 256 bits (recomendado para SHA-256)
TX_NONCE_BYTES = 16       # 128 bits de aleatoriedad para anti-replay
HKDF_INFO = b"cryptopay-settlement-hmac-v1"


# ==========================================
# 1. DERIVACIÓN DE CLAVE Y NONCE ANTI-REPLAY
# ==========================================

def derive_hmac_key(master_secret: bytes, salt: bytes = None) -> bytes:
    """
    Deriva una clave simétrica de 256 bits específica para HMAC-SHA256
    utilizando HKDF-SHA256. Evita usar claves maestras directamente o
    escribir claves fijas en el código fuente.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HMAC_KEY_LENGTH,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(master_secret)


def generate_tx_nonce() -> str:
    """
    Genera un nonce criptográficamente seguro de 128 bits (en hexadecimal)
    para identificar de forma única cada transferencia y evitar ataques
    de repetición (Replay Attacks).
    """
    return secrets.token_hex(TX_NONCE_BYTES)


# ==========================================
# 2. CONSTRUCCIÓN DEL MENSAJE CANÓNICO
# ==========================================

def _build_settlement_payload(
    tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    tx_nonce: str
) -> bytes:
    """
    Serializa los datos contables de la transferencia en un formato exacto
    y determinista (bytes UTF-8) para calcular o verificar el HMAC.
    Formatear amount con :.2f evita fallos entre 20.5 y 20.50.
    """
    canonical_str = f"{tx_id}|{sender}|{receiver}|{float(amount):.2f}|{tx_nonce}"
    return canonical_str.encode("utf-8")


# ==========================================
# 3. GENERACIÓN Y VERIFICACIÓN DE HMAC-SHA256
# ==========================================

def generate_settlement_hmac(
    hmac_key: bytes,
    tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    tx_nonce: str
) -> str:
    """
    Calcula la etiqueta HMAC-SHA256 sobre los datos de liquidación de la
    transferencia y la devuelve en hexadecimal para guardarla en el JSON.
    """
    payload = _build_settlement_payload(tx_id, sender, receiver, amount, tx_nonce)
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(payload)
    tag = h.finalize()
    return tag.hex()


def verify_settlement_hmac(
    hmac_key: bytes,
    tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    tx_nonce: str,
    expected_hmac_hex: str
) -> bool:
    """
    Verifica en tiempo constante que la etiqueta HMAC-SHA256 coincide con
    los datos de la transferencia. Devuelve False si algún dato o la propia
    etiqueta han sido manipulados.
    """
    try:
        expected_tag = bytes.fromhex(expected_hmac_hex)
        payload = _build_settlement_payload(tx_id, sender, receiver, amount, tx_nonce)
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(payload)
        h.verify(expected_tag)
        return True
    except (InvalidSignature, ValueError):
        return False


# Prueba rápida local de este módulo
if __name__ == "__main__":
    # Simulamos un secreto maestro generado en memoria (nunca fijo en el código)
    master_secret = secrets.token_bytes(32)
    hmac_key = derive_hmac_key(master_secret)

    tx_id = "tx-001"
    tx_nonce = generate_tx_nonce()

    # 1. Generamos el HMAC de una transferencia válida
    tag_hex = generate_settlement_hmac(hmac_key, tx_id, "ana", "carlos", 25.50, tx_nonce)
    print(f"[1] Nonce anti-replay (128b): {tx_nonce}")
    print(f"[2] Etiqueta HMAC-SHA256:     {tag_hex}")

    # 2. Prueba positiva
    ok = verify_settlement_hmac(hmac_key, tx_id, "ana", "carlos", 25.50, tx_nonce, tag_hex)
    print(f"[3] Verificación legítima:    {ok}")

    # 3. Prueba negativa: un atacante altera el importe de 25.50 a 2500.00
    tampered_amount = verify_settlement_hmac(hmac_key, tx_id, "ana", "carlos", 2500.00, tx_nonce, tag_hex)
    print(f"[4] Importe alterado (ataque): {tampered_amount}")

    # 4. Prueba negativa: un atacante altera el último carácter del HMAC
    fake_tag = tag_hex[:-1] + ("0" if tag_hex[-1] != "0" else "1")
    tampered_tag = verify_settlement_hmac(hmac_key, tx_id, "ana", "carlos", 25.50, tx_nonce, fake_tag)
    print(f"[5] HMAC alterado (ataque):    {tampered_tag}")