import getpass
import os
import secrets
import uuid
from datetime import datetime, timezone

# Importamos nuestra base de datos y los 4 módulos criptográficos
from src import database as db
from src.crypto import auth, encryption, mac, signatures

# Archivo local para el secreto maestro del servidor (excluido en .gitignore con *.key)
MASTER_KEY_FILE = "server_master.key"


# 1. GESTIÓN SEGURA DE LA CLAVE MAESTRA (HMAC)

def load_or_create_hmac_key() -> bytes:
    """
    Carga el secreto maestro desde un archivo local (o variable de entorno)
    y deriva la clave de 256 bits para HMAC-SHA256 usando HKDF.
    Nunca se escriben claves fijas en el código fuente.
    """
    # Si el archivo de clave maestra no existe todavía, lo generamos con 32 bytes aleatorios
    if not os.path.exists(MASTER_KEY_FILE):
        master_secret = secrets.token_bytes(32)
        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(master_secret)
        # Intentamos aplicar permisos restrictivos (solo lectura/escritura para el propietario)
        try:
            os.chmod(MASTER_KEY_FILE, 0o600)
        except OSError:
            pass  # En Windows chmod tiene efecto limitado, no detenemos la ejecución
    else:
        with open(MASTER_KEY_FILE, "rb") as f:
            master_secret = f.read()

    # Derivamos la clave específica para HMAC-SHA256 (256 bits) mediante HKDF
    return mac.derive_hmac_key(master_secret)


# 2. REGISTRO Y LOGIN DE USUARIOS (AUTH.PY)

def register_user() -> None:
    """Flujo completo de registro: validación, Scrypt, TOTP y generación de claves RSA/ECDSA."""
    print("\n--- REGISTRO DE NUEVO USUARIO ---")
    username = input("Nombre de usuario: ").strip().lower()

    if not username:
        print("[ERROR] El nombre de usuario no puede estar vacío.")
        return

    if db.get_user_by_username(username):
        print(f"[ERROR] El usuario '{username}' ya existe.")
        return

    # Pedimos la contraseña sin mostrarla por pantalla (getpass)
    password = getpass.getpass("Contraseña: ")
    confirm = getpass.getpass("Repite la contraseña: ")

    if password != confirm:
        print("[ERROR] Las contraseñas no coinciden.")
        return

    # Validamos la robustez de la contraseña
    is_valid, msg = auth.validate_password_strength(password)
    if not is_valid:
        print(f"[ERROR] {msg}")
        return

    print("Generando hash Scrypt y pares de claves asimétricas (RSA-2048 y ECDSA P-256)...")

    # Derivamos el hash con Scrypt + salt aleatorio de 16 bytes
    salt_hex, hash_hex = auth.hash_password(password)

    # Generamos la semilla TOTP (2FA)
    totp_secret = auth.generate_totp_secret()

    # Generamos los dos pares de claves asimétricas (privadas cifradas en PKCS#8 PEM)
    keys = auth.generate_user_keypairs(password)

    # Guardamos el usuario en cryptopay_data.json con saldo inicial de 100.00 €
    db.create_user(
        username=username,
        password_salt=salt_hex,
        password_hash=hash_hex,
        totp_secret=totp_secret,
        rsa_public_pem=keys["rsa_public_pem"],
        rsa_private_enc_pem=keys["rsa_private_enc_pem"],
        ecdsa_public_pem=keys["ecdsa_public_pem"],
        ecdsa_private_enc_pem=keys["ecdsa_private_enc_pem"],
        initial_balance=100.00,
    )

    # Registramos la operación en el log criptográfico (sin mostrar contraseñas ni claves)
    db.add_crypto_log(
        operation="REGISTRO_USUARIO",
        algorithm="Scrypt (256b) + TOTP + RSA-2048 + ECDSA P-256",
        details=f"Usuario '{username}' registrado con claves privadas protegidas en PKCS#8 PEM."
    )

    print(f"\n[OK] Usuario '{username}' creado con éxito (Saldo inicial: 100.00 €).")
    print(f"[2FA] Semilla TOTP asignada (guárdala para tu app 2FA): {totp_secret}")
    print(f"[2FA] Código temporal actual de prueba: {auth.get_current_totp_code(totp_secret)}")


def login_user() -> tuple[str | None, str | None]:
    """
    Autentica al usuario en dos factores:
    1) Contraseña verificada con Scrypt en tiempo constante.
    2) Código temporal TOTP de 6 dígitos.
    Devuelve (username, password) en memoria RAM si es correcto, o (None, None).
    """
    print("\n--- INICIO DE SESIÓN ---")
    username = input("Usuario: ").strip().lower()
    user = db.get_user_by_username(username)

    if not user:
        print("[ERROR] Credenciales incorrectas.")
        return None, None

    password = getpass.getpass("Contraseña: ")

    # Factor 1: Verificación de contraseña con Scrypt
    if not auth.verify_password(password, user["password_salt"], user["password_hash"]):
        db.add_crypto_log("LOGIN_FALLIDO", "Scrypt (256b)", f"Contraseña incorrecta para '{username}'.")
        print("[ERROR] Credenciales incorrectas.")
        return None, None

    # Mostramos el código TOTP actual solo como ayuda de depuración para la demo en clase
    print(f"Código TOTP actual para '{username}': {auth.get_current_totp_code(user['totp_secret'])}")
    totp_code = input("Introduce el código 2FA (6 dígitos): ").strip()

    # Factor 2: Verificación del código TOTP
    if not auth.verify_totp(user["totp_secret"], totp_code):
        db.add_crypto_log("LOGIN_FALLIDO_2FA", "TOTP (RFC 6238)", f"Código 2FA inválido para '{username}'.")
        print("[ERROR] Código 2FA inválido o caducado.")
        return None, None

    db.add_crypto_log("LOGIN_EXITOSO", "Scrypt + TOTP", f"Sesión iniciada para '{username}'.")
    print(f"\nBienvenido/a, {username}. Saldo actual: {user['balance']:.2f} €")
    return username, password


# 3. TRANSFERENCIA SEGURA (CIFRADO + FIRMA + HMAC)

def send_transfer(sender: str, password: str, hmac_key: bytes) -> None:
    """
    Realiza una transferencia P2P aplicando las 3 capas criptográficas:
    1) Cifrado híbrido del concepto (AES-256-GCM + RSA-2048-OAEP)
    2) Firma digital del emisor (ECDSA P-256 + SHA-256)
    3) Etiqueta de integridad contable (HMAC-SHA256 + Nonce anti-replay)
    """
    print("\n--- NUEVA TRANSFERENCIA SEGURA ---")
    receiver = input("Destinatario (usuario): ").strip().lower()

    if receiver == sender:
        print("[ERROR] No puedes enviarte dinero a ti mismo.")
        return

    receiver_data = db.get_user_by_username(receiver)
    if not receiver_data:
        print(f"[ERROR] El destinatario '{receiver}' no existe.")
        return

    try:
        amount = float(input("Importe (€): ").strip())
        if amount <= 0:
            print("[ERROR] El importe debe ser mayor que 0.")
            return
    except ValueError:
        print("[ERROR] Introduce un importe numérico válido.")
        return

    sender_data = db.get_user_by_username(sender)
    if sender_data["balance"] < amount:
        print(f"[ERROR] Saldo insuficiente (disponible: {sender_data['balance']:.2f} €).")
        return

    concept = input("Concepto privado (se cifrará de extremo a extremo): ").strip()
    if not concept:
        concept = "Sin concepto"

    # Generamos los identificadores únicos de la transferencia
    tx_id = f"tx-{uuid.uuid4().hex[:8]}"
    timestamp = datetime.now(timezone.utc).isoformat()
    tx_nonce = mac.generate_tx_nonce()

    # Comprobación anti-replay antes de procesar
    if db.is_nonce_used(tx_nonce):
        print("[ERROR] Nonce duplicado detectado (posible Replay Attack). Operación abortada.")
        return

    # PASO A: Cifrado híbrido del concepto (AES-256-GCM + RSA-2048-OAEP)
    enc_data = encryption.encrypt_transfer_concept(
        concept=concept,
        tx_id=tx_id,
        sender=sender,
        receiver=receiver,
        timestamp=timestamp,
        receiver_rsa_public_pem=receiver_data["rsa_public_pem"],
        sender_rsa_public_pem=sender_data["rsa_public_pem"],
    )
    db.add_crypto_log(
        "CIFRADO_HIBRIDO",
        "AES-256-GCM (clave 256b, nonce 96b) + RSA-2048-OAEP",
        f"Concepto cifrado para {tx_id} con AAD ligado a metadatos."
    )

    # PASO B: Firma digital del emisor (ECDSA P-256 + SHA-256)
    signature_hex = signatures.sign_transfer(
        sender_ecdsa_private_pem=sender_data["ecdsa_private_enc_pem"],
        password=password,
        tx_id=tx_id,
        sender=sender,
        receiver=receiver,
        amount=amount,
        timestamp=timestamp,
        tx_nonce=tx_nonce,
        aes_ciphertext_hex=enc_data["aes_ciphertext_hex"],
    )
    db.add_crypto_log(
        "FIRMA_DIGITAL",
        "ECDSA (SECP256R1 / 256b) + SHA-256",
        f"Transferencia {tx_id} firmada por '{sender}'."
    )

    # PASO C: Etiqueta HMAC-SHA256 sobre los datos contables
    settlement_hmac = mac.generate_settlement_hmac(
        hmac_key=hmac_key,
        tx_id=tx_id,
        sender=sender,
        receiver=receiver,
        amount=amount,
        tx_nonce=tx_nonce,
    )
    db.add_crypto_log(
        "GENERACION_MAC",
        "HMAC-SHA256 (clave 256b derivada con HKDF)",
        f"Sello contable generado para {tx_id}."
    )

    # Guardamos la transferencia completa en cryptopay_data.json y actualizamos saldos
    try:
        db.execute_transfer(
            tx_id=tx_id,
            sender=sender,
            receiver=receiver,
            amount=amount,
            timestamp=timestamp,
            aes_nonce=enc_data["aes_nonce_hex"],
            aes_ciphertext=enc_data["aes_ciphertext_hex"],
            enc_aes_key_receiver=enc_data["enc_aes_key_receiver_hex"],
            enc_aes_key_sender=enc_data["enc_aes_key_sender_hex"],
            ecdsa_signature=signature_hex,
            settlement_hmac=settlement_hmac,
            tx_nonce=tx_nonce,
        )
    except ValueError as err:
        print(f"[ERROR] No se pudo completar la transferencia: {err}")
        return

    print(f"\n  Transferencia {tx_id} enviada: {amount:.2f} € de '{sender}' a '{receiver}'.")
    print("     -> Concepto cifrado con AES-256-GCM + RSA-2048-OAEP.")
    print("     -> Firmada digitalmente con ECDSA P-256.")
    print("     -> Sellada con HMAC-SHA256 + Nonce anti-replay.")


# 4. HISTORIAL, VERIFICACIÓN Y DESCIFRADO

def view_history(username: str, password: str, hmac_key: bytes) -> None:
    """
    Lee las transferencias del usuario y verifica OBLIGATORIAMENTE:
    1) Integridad contable con HMAC-SHA256.
    2) Autenticidad y no repudio con la firma ECDSA del emisor.
    3) Descifrado autenticado (AES-256-GCM + RSA-OAEP) del concepto privado.
    Si falla cualquier verificación, rechaza los datos explícitamente.
    """
    print(f"\n--- HISTORIAL DE TRANSFERENCIAS DE '{username}' ---")
    transactions = db.get_user_transactions(username)

    if not transactions:
        print("No tienes transferencias registradas todavía.")
        return

    user_data = db.get_user_by_username(username)

    for tx in transactions:
        tx_id = tx["tx_id"]
        print(f"\n[Transferencia {tx_id}] {tx['sender']} -> {tx['receiver']} | {tx['amount']:.2f} € | {tx['timestamp']}")

        # 1. Verificación HMAC-SHA256
        hmac_ok = mac.verify_settlement_hmac(
            hmac_key=hmac_key,
            tx_id=tx_id,
            sender=tx["sender"],
            receiver=tx["receiver"],
            amount=tx["amount"],
            tx_nonce=tx["tx_nonce"],
            expected_hmac_hex=tx["settlement_hmac"],
        )
        db.add_crypto_log(
            "VERIFICACION_MAC",
            "HMAC-SHA256 (clave 256b)",
            f"{tx_id} -> {'VÁLIDO' if hmac_ok else 'INVÁLIDO (MANIPULADO)'}"
        )

        # 2. Verificación de Firma Digital ECDSA
        sender_data = db.get_user_by_username(tx["sender"])
        sig_ok = False
        if sender_data:
            sig_ok = signatures.verify_transfer_signature(
                sender_ecdsa_public_pem=sender_data["ecdsa_public_pem"],
                tx_id=tx_id,
                sender=tx["sender"],
                receiver=tx["receiver"],
                amount=tx["amount"],
                timestamp=tx["timestamp"],
                tx_nonce=tx["tx_nonce"],
                aes_ciphertext_hex=tx["aes_ciphertext"],
                signature_hex=tx["ecdsa_signature"],
            )
        db.add_crypto_log(
            "VERIFICACION_FIRMA",
            "ECDSA (SECP256R1 / 256b) + SHA-256",
            f"{tx_id} -> {'VÁLIDA' if sig_ok else 'INVÁLIDA (RECHAZADA)'}"
        )

        # Si falla el HMAC o la firma, rechazamos la transferencia y NO desciframos
        if not hmac_ok or not sig_ok:
            print(f"  [¡ALERTA DE SEGURIDAD!] Transferencia RECHAZADA (HMAC: {hmac_ok} | Firma ECDSA: {sig_ok}).")
            print("  Posible manipulación detectada en cryptopay_data.json.")
            continue

        # 3. Descifrado del concepto privado (elegimos el sobre RSA del emisor o del receptor)
        enc_aes_key_hex = (
            tx["enc_aes_key_sender"] if tx["sender"] == username else tx["enc_aes_key_receiver"]
        )
        try:
            concept = encryption.decrypt_transfer_concept(
                encrypted_aes_key_hex=enc_aes_key_hex,
                aes_nonce_hex=tx["aes_nonce"],
                aes_ciphertext_hex=tx["aes_ciphertext"],
                tx_id=tx_id,
                sender=tx["sender"],
                receiver=tx["receiver"],
                timestamp=tx["timestamp"],
                user_rsa_private_pem=user_data["rsa_private_enc_pem"],
                password=password,
            )
            print("  [OK] HMAC-SHA256: VÁLIDO | Firma ECDSA: VÁLIDA | AES-256-GCM: ÍNTEGRO")
            print(f"  Concepto descifrado: {concept}")
        except ValueError as err:
            print(f"  [¡ALERTA DE SEGURIDAD!] Error al descifrar concepto: {err}")


def view_logs() -> None:
    """Muestra los últimos 10 registros del log de auditoría criptográfica."""
    print("\n--- LOGS DE AUDITORÍA CRIPTOGRÁFICA (ÚLTIMOS 10) ---")
    logs = db.get_crypto_logs(limit=10)
    if not logs:
        print("No hay logs registrados todavía.")
        return
    for entry in logs:
        print(f"[{entry['timestamp']}] {entry['operation']} | {entry['algorithm']} -> {entry['details']}")


# 5. BUCLE PRINCIPAL DEL MENÚ

def main() -> None:
    # Inicializamos la base de datos JSON y cargamos/derivamos la clave HMAC
    db.init_db()
    hmac_key = load_or_create_hmac_key()

    current_user = None
    current_password = None

    print("===================================")
    print("   CRYPTOPAY - Pagos Seguros   ")
    print("===================================")

    while True:
        if current_user is None:
            # Menú sin sesión iniciada
            print("\n1. Registrarse")
            print("2. Iniciar sesión (2FA)")
            print("3. Ver logs criptográficos")
            print("4. Salir")
            choice = input("Elige una opción: ").strip()

            if choice == "1":
                register_user()
            elif choice == "2":
                current_user, current_password = login_user()
            elif choice == "3":
                view_logs()
            elif choice == "4":
                print("Saliendo de CryptoPay...")
                break
            else:
                print("[ERROR] Opción no válida.")
        else:
            # Menú con sesión iniciada
            user_info = db.get_user_by_username(current_user)
            print(f"\n--- SESIÓN ACTIVA: {current_user} (Saldo: {user_info['balance']:.2f} €) ---")
            print("1. Enviar transferencia segura")
            print("2. Ver historial (verificar firmas/HMAC y descifrar conceptos)")
            print("3. Ver logs criptográficos")
            print("4. Cerrar sesión")
            choice = input("Elige una opción: ").strip()

            if choice == "1":
                send_transfer(current_user, current_password, hmac_key)
            elif choice == "2":
                view_history(current_user, current_password, hmac_key)
            elif choice == "3":
                view_logs()
            elif choice == "4":
                # Borramos las credenciales de la memoria al cerrar sesión
                current_user = None
                current_password = None
                print("Sesión cerrada correctamente.")
            else:
                print("[ERROR] Opción no válida.")


if __name__ == "__main__":
    main()