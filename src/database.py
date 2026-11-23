import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

DEFAULT_DB_PATH = "cryptopay_data.json"
_db_lock = threading.Lock()


def _empty_structure() -> Dict[str, Any]:
    """Estructura base del archivo JSON de CryptoPay."""
    return {
        "users": {},          # Diccionario indexado por username
        "transactions": [],   # Lista de transferencias
        "used_nonces": {},    # Diccionario {tx_nonce: used_at} para anti-replay
        "crypto_logs": []     # Lista de eventos de auditoría criptográfica
    }


def _load_data(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Lee y devuelve el contenido del archivo JSON."""
    if not os.path.exists(db_path):
        init_db(db_path)
    with open(db_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_data(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> None:
    """Guarda el diccionario en el archivo JSON con formato legible."""
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Crea el archivo JSON inicial de CryptoPay si no existe."""
    with _db_lock:
        if not os.path.exists(db_path):
            _save_data(_empty_structure(), db_path)


# ==========================================
# GESTIÓN DE USUARIOS
# ==========================================

def create_user(
    username: str,
    password_salt: str,
    password_hash: str,
    totp_secret: str,
    rsa_public_pem: str,
    rsa_private_enc_pem: str,
    ecdsa_public_pem: str,
    ecdsa_private_enc_pem: str,
    initial_balance: float = 100.00,
    db_path: str = DEFAULT_DB_PATH
) -> bool:
    """Registra un nuevo usuario en CryptoPay. Devuelve False si ya existe."""
    with _db_lock:
        data = _load_data(db_path)
        if username in data["users"]:
            return False

        data["users"][username] = {
            "username": username,
            "password_salt": password_salt,
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "rsa_public_pem": rsa_public_pem,
            "rsa_private_enc_pem": rsa_private_enc_pem,
            "ecdsa_public_pem": ecdsa_public_pem,
            "ecdsa_private_enc_pem": ecdsa_private_enc_pem,
            "balance": round(float(initial_balance), 2)
        }
        _save_data(data, db_path)
        return True


def get_user_by_username(username: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Recupera todos los datos de un usuario por su username."""
    with _db_lock:
        data = _load_data(db_path)
        user = data["users"].get(username)
        return dict(user) if user else None


def list_usernames(db_path: str = DEFAULT_DB_PATH) -> List[str]:
    """Devuelve la lista ordenada de usuarios registrados."""
    with _db_lock:
        data = _load_data(db_path)
        return sorted(data["users"].keys())


# ==========================================
# TRANSFERENCIAS Y CONTROL ANTI-REPLAY
# ==========================================

def is_nonce_used(tx_nonce: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Comprueba si un nonce de transacción ya fue utilizado."""
    with _db_lock:
        data = _load_data(db_path)
        return tx_nonce in data["used_nonces"]


def execute_transfer(
    tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    timestamp: str,
    aes_nonce: str,
    aes_ciphertext: str,
    enc_aes_key_receiver: str,
    enc_aes_key_sender: str,
    ecdsa_signature: str,
    settlement_hmac: str,
    tx_nonce: str,
    db_path: str = DEFAULT_DB_PATH
) -> None:
    """
    Ejecuta la transferencia verificando control anti-replay y saldo.
    Si algo falla, no se guarda ningún cambio en el JSON.
    """
    with _db_lock:
        data = _load_data(db_path)

        # 1. Control Anti-Replay
        if tx_nonce in data["used_nonces"]:
            raise ValueError("Ataque de repetición detectado: el nonce ya ha sido consumido.")

        # 2. Validar existencia de usuarios y saldo del emisor
        if sender not in data["users"] or receiver not in data["users"]:
            raise ValueError("El emisor o el receptor no existen.")

        if data["users"][sender]["balance"] < amount:
            raise ValueError("Saldo insuficiente para realizar la transferencia.")

        # 3. Actualizar saldos
        data["users"][sender]["balance"] = round(data["users"][sender]["balance"] - amount, 2)
        data["users"][receiver]["balance"] = round(data["users"][receiver]["balance"] + amount, 2)

        # 4. Guardar transacción
        data["transactions"].append({
            "tx_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "amount": round(float(amount), 2),
            "timestamp": timestamp,
            "aes_nonce": aes_nonce,
            "aes_ciphertext": aes_ciphertext,
            "enc_aes_key_receiver": enc_aes_key_receiver,
            "enc_aes_key_sender": enc_aes_key_sender,
            "ecdsa_signature": ecdsa_signature,
            "settlement_hmac": settlement_hmac,
            "tx_nonce": tx_nonce
        })

        # 5. Marcar nonce como consumido
        data["used_nonces"][tx_nonce] = datetime.now(timezone.utc).isoformat()

        # Solo se escribe en disco si todos los pasos anteriores tuvieron éxito
        _save_data(data, db_path)


def get_user_transactions(username: str, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Devuelve todas las transferencias enviadas o recibidas por un usuario."""
    with _db_lock:
        data = _load_data(db_path)
        user_txs = [
            dict(tx) for tx in data["transactions"]
            if tx["sender"] == username or tx["receiver"] == username
        ]
        # Ordenar de más reciente a más antigua
        user_txs.sort(key=lambda x: x["timestamp"], reverse=True)
        return user_txs


def get_transaction_by_id(tx_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Recupera una transacción concreta por su UUID."""
    with _db_lock:
        data = _load_data(db_path)
        for tx in data["transactions"]:
            if tx["tx_id"] == tx_id:
                return dict(tx)
        return None


# ==========================================
# REGISTRO DE AUDITORÍA CRIPTOGRÁFICA
# ==========================================

def add_crypto_log(
    operation: str,
    algorithm: str,
    details: str,
    db_path: str = DEFAULT_DB_PATH
) -> None:
    """Registra una operación criptográfica pública para la consola de depuración."""
    with _db_lock:
        data = _load_data(db_path)
        next_id = len(data["crypto_logs"]) + 1
        data["crypto_logs"].append({
            "id": next_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "operation": operation,
            "algorithm": algorithm,
            "details": details
        })
        _save_data(data, db_path)


def get_crypto_logs(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Obtiene los últimos registros de auditoría (del más reciente al más antiguo)."""
    with _db_lock:
        data = _load_data(db_path)
        return list(reversed(data["crypto_logs"][-limit:]))


# ==========================================
# SIMULADOR DE ATAQUES (PARA DEMOSTRACIÓN)
# ==========================================

def tamper_transaction(
    tx_id: str,
    field: str,
    new_value: Any,
    db_path: str = DEFAULT_DB_PATH
) -> bool:
    """
    Altera deliberadamente un campo de una transacción en el JSON para demostrar
    en vivo cómo fallan AES-GCM, ECDSA o HMAC ante manipulaciones.
    """
    allowed_fields = {"amount", "aes_ciphertext", "ecdsa_signature", "settlement_hmac"}
    if field not in allowed_fields:
        raise ValueError(f"Campo no permitido para simulación de ataque: {field}")

    with _db_lock:
        data = _load_data(db_path)
        for tx in data["transactions"]:
            if tx["tx_id"] == tx_id:
                tx[field] = new_value
                _save_data(data, db_path)
                return True
        return False


if __name__ == "__main__":
    init_db()
    print("[OK] Archivo 'cryptopay_data.json' inicializado correctamente.")