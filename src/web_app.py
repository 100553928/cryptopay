import os
import sys
import uuid
from datetime import datetime, timezone

import streamlit as st
from cryptography.exceptions import InvalidTag

# Aseguramos que Python encuentre el paquete 'src' al lanzar con streamlit run
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import database as db
from src.app import load_or_create_hmac_key
from src.crypto import auth, encryption, mac, signatures

# Configuración básica de la pestaña del navegador
st.set_page_config(page_title="CryptoPay", page_icon="💳", layout="centered")

# Inicializamos la base de datos y cargamos la clave HMAC compartida con la terminal
db.init_db()
hmac_key = load_or_create_hmac_key()

# Variables de sesión en memoria (equivalente a current_user / current_password en app.py)
if "user" not in st.session_state:
    st.session_state.user = None
if "password" not in st.session_state:
    st.session_state.password = None
if "pending_user" not in st.session_state:
    st.session_state.pending_user = None
if "pending_password" not in st.session_state:
    st.session_state.pending_password = None


# ==========================================
# 1. PANTALLA DE ACCESO (LOGIN 2FA Y REGISTRO)
# ==========================================

def show_auth_screen() -> None:
    st.title("💳 CryptoPay")
    st.caption("Pagos P2P seguros con Scrypt + TOTP, AES-256-GCM + RSA-2048, ECDSA P-256 y HMAC-SHA256")

    tab_login, tab_register, tab_logs = st.tabs(["Iniciar sesión (2FA)", "Registrarse", "Logs criptográficos"])

    # --- PESTAÑA 1: INICIO DE SESIÓN EN 2 PASOS ---
    with tab_login:
        # Paso 1: Usuario y contraseña (Scrypt)
        if st.session_state.pending_user is None:
            with st.form("login_step1"):
                username_in = st.text_input("Usuario", placeholder="ej. Ana").strip().lower()
                password_in = st.text_input("Contraseña", type="password")
                submit_step1 = st.form_submit_button("Continuar", use_container_width=True, type="primary")

            if submit_step1:
                user = db.get_user_by_username(username_in)
                if not user or not auth.verify_password(password_in, user["password_salt"], user["password_hash"]):
                    if user:
                        db.add_crypto_log("LOGIN_FALLIDO", "Scrypt (256b)", f"Contraseña incorrecta para '{username_in}'.")
                    st.error("Credenciales incorrectas.")
                else:
                    # Contraseña válida: pasamos al Paso 2 (TOTP)
                    st.session_state.pending_user = username_in
                    st.session_state.pending_password = password_in
                    st.rerun()

        # Paso 2: Verificación 2FA (TOTP)
        else:
            pending = st.session_state.pending_user
            user_data = db.get_user_by_username(pending)
            current_code = auth.get_current_totp_code(user_data["totp_secret"])

            st.info(f"Código TOTP actual para **{pending.capitalize()}**: `{current_code}` *(caduca en 30 segundos)*")

            with st.form("login_step2"):
                totp_in = st.text_input("Introduce el código 2FA (6 dígitos)", max_chars=6).strip()
                col1, col2 = st.columns(2)
                verify_btn = col1.form_submit_button("Verificar y entrar", use_container_width=True, type="primary")
                cancel_btn = col2.form_submit_button("Cancelar", use_container_width=True)

            if cancel_btn:
                st.session_state.pending_user = None
                st.session_state.pending_password = None
                st.rerun()

            if verify_btn:
                if auth.verify_totp(user_data["totp_secret"], totp_in):
                    db.add_crypto_log("LOGIN_EXITOSO", "Scrypt + TOTP", f"Sesión iniciada para '{pending}' (Web).")
                    st.session_state.user = pending
                    st.session_state.password = st.session_state.pending_password
                    st.session_state.pending_user = None
                    st.session_state.pending_password = None
                    st.rerun()
                else:
                    db.add_crypto_log("LOGIN_FALLIDO_2FA", "TOTP (RFC 6238)", f"Código 2FA inválido para '{pending}'.")
                    st.error("Código 2FA inválido o caducado.")

    # --- PESTAÑA 2: REGISTRO DE NUEVO USUARIO ---
    with tab_register:
        with st.form("register_form"):
            new_user = st.text_input("Nombre de usuario", placeholder="ej. Carlos").strip().lower()
            new_pwd = st.text_input("Contraseña", type="password", help="Mín. 8 caracteres, mayúscula, minúscula, número y símbolo.")
            confirm_pwd = st.text_input("Repite la contraseña", type="password")
            reg_btn = st.form_submit_button("Crear cuenta", use_container_width=True, type="primary")

        if reg_btn:
            if not new_user:
                st.error("El nombre de usuario no puede estar vacío.")
            elif db.get_user_by_username(new_user):
                st.error(f"El usuario '{new_user.capitalize()}' ya existe.")
            elif new_pwd != confirm_pwd:
                st.error("Las contraseñas no coinciden.")
            else:
                ok, msg = auth.validate_password_strength(new_pwd)
                if not ok:
                    st.error(msg)
                else:
                    with st.spinner("Generando hash Scrypt y claves RSA-2048 / ECDSA P-256..."):
                        salt_hex, hash_hex = auth.hash_password(new_pwd)
                        totp_secret = auth.generate_totp_secret()
                        keys = auth.generate_user_keypairs(new_pwd)

                        db.create_user(
                            username=new_user,
                            password_salt=salt_hex,
                            password_hash=hash_hex,
                            totp_secret=totp_secret,
                            rsa_public_pem=keys["rsa_public_pem"],
                            rsa_private_enc_pem=keys["rsa_private_enc_pem"],
                            ecdsa_public_pem=keys["ecdsa_public_pem"],
                            ecdsa_private_enc_pem=keys["ecdsa_private_enc_pem"],
                            initial_balance=100.00,
                        )
                        db.add_crypto_log(
                            "REGISTRO_USUARIO",
                            "Scrypt (256b) + TOTP + RSA-2048 + ECDSA P-256",
                            f"Usuario '{new_user}' registrado con claves privadas protegidas en PKCS#8 PEM.",
                        )
                    st.success(f"Usuario **{new_user.capitalize()}** creado con éxito (Saldo inicial: 100.00 €).")
                    st.info(f"Semilla TOTP asignada: `{totp_secret}`")

    # --- PESTAÑA 3: LOGS PÚBLICOS ---
    with tab_logs:
        show_logs_section()


# ==========================================
# 2. PANEL PRINCIPAL (ESTILO PAYPAL / BIZUM)
# ==========================================

def show_dashboard() -> None:
    username = st.session_state.user
    password = st.session_state.password
    user_data = db.get_user_by_username(username)

    # Cabecera con nombre, saldo y botón de cerrar sesión
    col_title, col_logout = st.columns([4, 1])
    with col_title:
        st.title(f"💳 Hola, {username.capitalize()}")
    with col_logout:
        st.write("")
        if st.button("Cerrar sesión", use_container_width=True):
            st.session_state.user = None
            st.session_state.password = None
            st.rerun()

    st.metric(label="Saldo disponible", value=f"{user_data['balance']:.2f} €")
    st.divider()

    tab_send, tab_history, tab_logs = st.tabs(["💸 Enviar dinero", "📜 Historial verificado", "🛡️ Logs criptográficos"])

    # --- PESTAÑA 1: ENVIAR TRANSFERENCIA ---
    with tab_send:
        other_users = [u for u in db.list_usernames() if u != username]
        if not other_users:
            st.warning("No hay otros usuarios registrados todavía para enviarles dinero.")
        else:
            with st.form("send_tx_form"):
                receiver = st.selectbox(
                    "Destinatario",
                    options=other_users,
                    format_func=lambda u: u.capitalize(),
                )
                amount = st.number_input("Importe (€)", min_value=0.01, max_value=10000.0, value=10.00, step=1.00)
                concept = st.text_input("Concepto privado (cifrado E2E)", placeholder="ej. Cena del viernes").strip()
                send_btn = st.form_submit_button("Enviar transferencia segura", use_container_width=True, type="primary")

            if send_btn:
                if user_data["balance"] < amount:
                    st.error(f"Saldo insuficiente (disponible: {user_data['balance']:.2f} €).")
                else:
                    receiver_data = db.get_user_by_username(receiver)
                    concept_text = concept if concept else "Sin concepto"
                    tx_id = f"tx-{uuid.uuid4().hex[:8]}"
                    timestamp = datetime.now(timezone.utc).isoformat()
                    tx_nonce = mac.generate_tx_nonce()

                    if db.is_nonce_used(tx_nonce):
                        st.error("Nonce duplicado detectado (Replay Attack). Operación abortada.")
                    else:
                        # 1) Cifrado híbrido (AES-256-GCM + RSA-2048-OAEP)
                        enc_data = encryption.encrypt_transfer_concept(
                            concept=concept_text,
                            tx_id=tx_id,
                            sender=username,
                            receiver=receiver,
                            timestamp=timestamp,
                            receiver_rsa_public_pem=receiver_data["rsa_public_pem"],
                            sender_rsa_public_pem=user_data["rsa_public_pem"],
                        )
                        db.add_crypto_log(
                            "CIFRADO_HIBRIDO",
                            "AES-256-GCM (clave 256b, nonce 96b) + RSA-2048-OAEP",
                            f"Concepto cifrado para {tx_id} con AAD ligado a metadatos.",
                        )

                        # 2) Firma digital (ECDSA P-256 + SHA-256)
                        signature_hex = signatures.sign_transfer(
                            sender_ecdsa_private_pem=user_data["ecdsa_private_enc_pem"],
                            password=password,
                            tx_id=tx_id,
                            sender=username,
                            receiver=receiver,
                            amount=amount,
                            timestamp=timestamp,
                            tx_nonce=tx_nonce,
                            aes_ciphertext_hex=enc_data["aes_ciphertext_hex"],
                        )
                        db.add_crypto_log(
                            "FIRMA_DIGITAL",
                            "ECDSA (SECP256R1 / 256b) + SHA-256",
                            f"Transferencia {tx_id} firmada por '{username}'.",
                        )

                        # 3) Integridad contable (HMAC-SHA256)
                        settlement_hmac = mac.generate_settlement_hmac(
                            hmac_key=hmac_key,
                            tx_id=tx_id,
                            sender=username,
                            receiver=receiver,
                            amount=amount,
                            tx_nonce=tx_nonce,
                        )
                        db.add_crypto_log(
                            "GENERACION_MAC",
                            "HMAC-SHA256 (clave 256b derivada con HKDF)",
                            f"Sello contable generado para {tx_id}.",
                        )

                        try:
                            db.execute_transfer(
                                tx_id=tx_id,
                                sender=username,
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
                            st.success(f"Transferencia **{tx_id}** enviada: **{amount:.2f} €** a **{receiver.capitalize()}**.")
                            st.rerun()
                        except ValueError as err:
                            st.error(f"Error al completar la transferencia: {err}")

    # --- PESTAÑA 2: HISTORIAL CON VERIFICACIÓN AUTOMÁTICA ---
    with tab_history:
        transactions = db.get_user_transactions(username)
        if not transactions:
            st.info("No tienes transferencias registradas todavía.")
        else:
            for tx in transactions:
                tx_id = tx["tx_id"]
                is_sender = tx["sender"] == username
                sign = "-" if is_sender else "+"

                # Verificación HMAC-SHA256
                hmac_ok = mac.verify_settlement_hmac(
                    hmac_key=hmac_key,
                    tx_id=tx_id,
                    sender=tx["sender"],
                    receiver=tx["receiver"],
                    amount=tx["amount"],
                    tx_nonce=tx["tx_nonce"],
                    expected_hmac_hex=tx["settlement_hmac"],
                )

                # Verificación Firma ECDSA
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

                with st.container(border=True):
                    c1, c2 = st.columns([3, 1])
                    c1.markdown(f"**{tx['sender'].capitalize()} ➔ {tx['receiver'].capitalize()}** · `{tx_id}`")
                    c2.markdown(f"### {sign}{tx['amount']:.2f} €")
                    st.caption(f"Fecha UTC: {tx['timestamp']}")

                    if not hmac_ok or not sig_ok:
                        st.error(
                            f"¡ALERTA DE SEGURIDAD! Transferencia RECHAZADA "
                            f"(HMAC: {'OK' if hmac_ok else 'INVÁLIDO'} | Firma ECDSA: {'OK' if sig_ok else 'INVÁLIDA'}). "
                            f"Posible manipulación detectada en cryptopay_data.json."
                        )
                    else:
                        enc_aes_key_hex = tx["enc_aes_key_sender"] if is_sender else tx["enc_aes_key_receiver"]
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
                            st.success("HMAC-SHA256: Válido · Firma ECDSA: Válida · AES-256-GCM: Íntegro")
                            st.write(f"**Concepto descifrado:** {concept}")
                        except (ValueError, InvalidTag) as err:
                            st.error(f"¡ALERTA DE SEGURIDAD! Error al descifrar concepto: {err}")

    # --- PESTAÑA 3: LOGS DE AUDITORÍA ---
    with tab_logs:
        show_logs_section()


def show_logs_section() -> None:
    logs = db.get_crypto_logs(limit=20)
    if not logs:
        st.info("No hay logs registrados todavía.")
    else:
        st.dataframe(logs, use_container_width=True, hide_index=True)


# Punto de entrada
if st.session_state.user is None:
    show_auth_screen()
else:
    show_dashboard()