import sqlite3
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

DEFAULT_DB_PATH = "cryptopay.db"


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Crea y devuelve una conexión a SQLite con acceso por nombre de columna."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Inicializa las 4 tablas principales del sistema CryptoPay."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # 1. Tabla de usuarios y custodia de claves
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                rsa_public_pem TEXT NOT NULL,
                rsa_private_enc_pem TEXT NOT NULL,
                ecdsa_public_pem TEXT NOT NULL,
                ecdsa_private_enc_pem TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 100.00
            )
        """)

        # 2. Tabla de transferencias (cifrado híbrido + firma + HMAC)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                tx_id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp TEXT NOT NULL,
                aes_nonce TEXT NOT NULL,
                aes_ciphertext TEXT NOT NULL,
                enc_aes_key_receiver TEXT NOT NULL,
                enc_aes_key_sender TEXT NOT NULL,
                ecdsa_signature TEXT NOT NULL,
                settlement_hmac TEXT NOT NULL,
                tx_nonce TEXT UNIQUE NOT NULL,
                FOREIGN KEY (sender) REFERENCES users(username),
                FOREIGN KEY (receiver) REFERENCES users(username)
            )
        """)

        # 3. Tabla anti-replay (registro de nonces ya consumidos)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS used_nonces (
                tx_nonce TEXT PRIMARY KEY,
                used_at TEXT NOT NULL
            )
        """)

        # 4. Tabla de logs criptográficos (NUNCA almacena claves secretas ni contraseñas)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS crypto_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)

        conn.commit()


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
    """Registra un nuevo usuario. Devuelve False si el username ya existe."""
    try:
        with get_connection(db_path) as conn:
            conn.execute("""
                INSERT INTO users (
                    username, password_salt, password_hash, totp_secret,
                    rsa_public_pem, rsa_private_enc_pem,
                    ecdsa_public_pem, ecdsa_private_enc_pem, balance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                username, password_salt, password_hash, totp_secret,
                rsa_public_pem, rsa_private_enc_pem,
                ecdsa_public_pem, ecdsa_private_enc_pem, initial_balance
            ))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user_by_username(username: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Recupera todos los datos de un usuario por su username."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None


def list_usernames(db_path: str = DEFAULT_DB_PATH) -> List[str]:
    """Devuelve la lista de usuarios registrados (útil para el selector de destinatarios)."""
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT username FROM users ORDER BY username ASC").fetchall()
        return [row["username"] for row in rows]


# ==========================================
# TRANSFERENCIAS Y CONTROL ANTI-REPLAY
# ==========================================

def is_nonce_used(tx_nonce: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Comprueba si un nonce de transacción ya fue utilizado (defensa contra Replay Attack)."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM used_nonces WHERE tx_nonce = ?", (tx_nonce,)
        ).fetchone()
        return row is not None


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
    Ejecuta la transferencia de forma atómica:
    1. Verifica que el nonce no haya sido usado.
    2. Actualiza saldos de emisor y receptor.
    3. Guarda la transacción cifrada/firmada y registra el nonce.
    Lanza ValueError si hay saldo insuficiente o ataque de repetición.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("BEGIN")

        # 1. Control Anti-Replay
        if cursor.execute("SELECT 1 FROM used_nonces WHERE tx_nonce = ?", (tx_nonce,)).fetchone():
            raise ValueError("Ataque de repetición detectado: el nonce ya ha sido consumido.")

        # 2. Comprobar saldo del emisor
        sender_row = cursor.execute(
            "SELECT balance FROM users WHERE username = ?", (sender,)
        ).fetchone()
        if not sender_row or sender_row["balance"] < amount:
            raise ValueError("Saldo insuficiente para realizar la transferencia.")

        # 3. Actualizar saldos
        cursor.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, sender))
        cursor.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, receiver))

        # 4. Guardar transacción
        cursor.execute("""
            INSERT INTO transactions (
                tx_id, sender, receiver, amount, timestamp,
                aes_nonce, aes_ciphertext, enc_aes_key_receiver, enc_aes_key_sender,
                ecdsa_signature, settlement_hmac, tx_nonce
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tx_id, sender, receiver, amount, timestamp,
            aes_nonce, aes_ciphertext, enc_aes_key_receiver, enc_aes_key_sender,
            ecdsa_signature, settlement_hmac, tx_nonce
        ))

        # 5. Marcar nonce como consumido
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO used_nonces (tx_nonce, used_at) VALUES (?, ?)",
            (tx_nonce, now_iso)
        )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_user_transactions(username: str, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Devuelve todas las transferencias enviadas o recibidas por un usuario."""
    with get_connection(db_path) as conn:
        rows = conn.execute("""
            SELECT * FROM transactions
            WHERE sender = ? OR receiver = ?
            ORDER BY timestamp DESC
        """, (username, username)).fetchall()
        return [dict(row) for row in rows]


def get_transaction_by_id(tx_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Recupera una transacción concreta por su UUID."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM transactions WHERE tx_id = ?", (tx_id,)
        ).fetchone()
        return dict(row) if row else None


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
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO crypto_logs (timestamp, operation, algorithm, details)
            VALUES (?, ?, ?, ?)
        """, (timestamp, operation, algorithm, details))
        conn.commit()


def get_crypto_logs(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Obtiene los últimos registros de auditoría para mostrarlos en la interfaz."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM crypto_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


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
    Altera deliberadamente un campo de una transacción en BD para demostrar
    en vivo cómo fallan AES-GCM, ECDSA o HMAC ante manipulaciones.
    """
    allowed_fields = {"amount", "aes_ciphertext", "ecdsa_signature", "settlement_hmac"}
    if field not in allowed_fields:
        raise ValueError(f"Campo no permitido para simulación de ataque: {field}")

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            f"UPDATE transactions SET {field} = ? WHERE tx_id = ?",
            (new_value, tx_id)
        )
        conn.commit()
        return cursor.rowcount > 0


# Prueba rápida si se ejecuta este archivo directamente
if __name__ == "__main__":
    init_db()
    print("[OK] Base de datos 'cryptopay.db' inicializada correctamente con las 4 tablas.")