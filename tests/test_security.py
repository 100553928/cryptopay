import secrets
import pytest
from cryptography.exceptions import InvalidTag

from src import database as db
from src.crypto import auth, encryption, mac, signatures

# DATOS DE PRUEBA REUTILIZABLES

@pytest.fixture(scope="module")
def users_keys():
    """
    Genera una sola vez los pares de claves (RSA-2048 y ECDSA P-256)
    para tres usuarios de prueba: Ana (emisor), Carlos (receptor) y Eva (atacante).
    """
    return {
        "ana_pwd": "ClaveAna2026!",
        "ana_keys": auth.generate_user_keypairs("ClaveAna2026!"),
        "carlos_pwd": "ClaveCarlos2026!",
        "carlos_keys": auth.generate_user_keypairs("ClaveCarlos2026!"),
        "eva_pwd": "ClaveEva2026!",
        "eva_keys": auth.generate_user_keypairs("ClaveEva2026!"),
    }


@pytest.fixture(scope="module")
def hmac_key():
    """Deriva una clave HMAC-SHA256 de 256 bits en memoria para los tests."""
    master_secret = secrets.token_bytes(32)
    return mac.derive_hmac_key(master_secret)


# 1. TESTS DE AUTENTICACIÓN (AUTH.PY)

def test_password_strength_positive_and_negative():
    """
    Comprueba que la política de contraseñas acepta claves robustas
    y rechaza claves cortas o sin mayúsculas, números o símbolos.
    """
    ok, _ = auth.validate_password_strength("Segura2026!")
    assert ok is True

    # Negativos: demasiado corta, sin mayúscula, sin número, sin símbolo
    assert auth.validate_password_strength("Ab1!")[0] is False
    assert auth.validate_password_strength("minuscula2026!")[0] is False
    assert auth.validate_password_strength("SinNumero!")[0] is False
    assert auth.validate_password_strength("SinSimbolo2026")[0] is False


def test_scrypt_hash_and_wrong_password():
    """
    Prueba positiva y negativa de Scrypt:
    - Verifica que la contraseña correcta pasa.
    - Verifica que una contraseña incorrecta es rechazada.
    - Verifica que dos hashes de la misma contraseña usan sales distintas.
    """
    pwd = "MiPassword2026#"
    salt1, hash1 = auth.hash_password(pwd)
    salt2, hash2 = auth.hash_password(pwd)

    # Misma contraseña -> salts y hashes distintos (protección contra Rainbow Tables)
    assert salt1 != salt2
    assert hash1 != hash2

    # Positivo: contraseña correcta
    assert auth.verify_password(pwd, salt1, hash1) is True
    # Negativo: contraseña incorrecta
    assert auth.verify_password("PasswordFalsa2026#", salt1, hash1) is False


def test_totp_2fa_valid_and_invalid():
    """
    Comprueba el segundo factor de autenticación (TOTP RFC 6238):
    acepta el código actual y rechaza códigos inventados o con letras.
    """
    secret = auth.generate_totp_secret()
    valid_code = auth.get_current_totp_code(secret)

    assert auth.verify_totp(secret, valid_code) is True
    assert auth.verify_totp(secret, "000000") is False
    assert auth.verify_totp(secret, "abcdef") is False


# 2. TESTS DE CIFRADO HÍBRIDO (ENCRYPTION.PY)

def test_hybrid_encryption_positive_sender_and_receiver(users_keys):
    """
    Prueba positiva: Ana cifra un concepto para Carlos con AES-256-GCM + RSA-2048-OAEP.
    Tanto Carlos (receptor) como Ana (emisor) deben poder descifrarlo con su propia clave privada.
    """
    concept = "Pago cena del viernes - 25.50 EUR"
    enc = encryption.encrypt_transfer_concept(
        concept=concept,
        tx_id="tx-100",
        sender="ana",
        receiver="carlos",
        timestamp="2026-11-27T10:00:00+00:00",
        receiver_rsa_public_pem=users_keys["carlos_keys"]["rsa_public_pem"],
        sender_rsa_public_pem=users_keys["ana_keys"]["rsa_public_pem"],
    )

    # Descifrado por el receptor (Carlos)
    dec_carlos = encryption.decrypt_transfer_concept(
        encrypted_aes_key_hex=enc["enc_aes_key_receiver_hex"],
        aes_nonce_hex=enc["aes_nonce_hex"],
        aes_ciphertext_hex=enc["aes_ciphertext_hex"],
        tx_id="tx-100",
        sender="ana",
        receiver="carlos",
        timestamp="2026-11-27T10:00:00+00:00",
        user_rsa_private_pem=users_keys["carlos_keys"]["rsa_private_enc_pem"],
        password=users_keys["carlos_pwd"],
    )
    assert dec_carlos == concept

    # Descifrado por el emisor (Ana)
    dec_ana = encryption.decrypt_transfer_concept(
        encrypted_aes_key_hex=enc["enc_aes_key_sender_hex"],
        aes_nonce_hex=enc["aes_nonce_hex"],
        aes_ciphertext_hex=enc["aes_ciphertext_hex"],
        tx_id="tx-100",
        sender="ana",
        receiver="carlos",
        timestamp="2026-11-27T10:00:00+00:00",
        user_rsa_private_pem=users_keys["ana_keys"]["rsa_private_enc_pem"],
        password=users_keys["ana_pwd"],
    )
    assert dec_ana == concept


def test_encryption_negative_tampered_ciphertext(users_keys):
    """
    Prueba negativa: Un atacante altera un carácter del texto cifrado (ciphertext/tag).
    AES-256-GCM debe detectar la manipulación y lanzar InvalidTag o ValueError.
    """
    enc = encryption.encrypt_transfer_concept(
        concept="Secreto",
        tx_id="tx-101",
        sender="ana",
        receiver="carlos",
        timestamp="2026-11-27T10:00:00+00:00",
        receiver_rsa_public_pem=users_keys["carlos_keys"]["rsa_public_pem"],
        sender_rsa_public_pem=users_keys["ana_keys"]["rsa_public_pem"],
    )

    # Alteramos el último carácter hexadecimal del ciphertext
    ct = enc["aes_ciphertext_hex"]
    tampered_ct = ct[:-1] + ("0" if ct[-1] != "0" else "1")

    with pytest.raises((InvalidTag, ValueError)):
        encryption.decrypt_transfer_concept(
            encrypted_aes_key_hex=enc["enc_aes_key_receiver_hex"],
            aes_nonce_hex=enc["aes_nonce_hex"],
            aes_ciphertext_hex=tampered_ct,
            tx_id="tx-101",
            sender="ana",
            receiver="carlos",
            timestamp="2026-11-27T10:00:00+00:00",
            user_rsa_private_pem=users_keys["carlos_keys"]["rsa_private_enc_pem"],
            password=users_keys["carlos_pwd"],
        )


def test_encryption_negative_tampered_aad_metadata(users_keys):
    """
    Prueba negativa: El texto cifrado está intacto, pero un atacante cambia el timestamp
    (metadato público ligado al AAD). AES-256-GCM debe rechazar el descifrado.
    """
    enc = encryption.encrypt_transfer_concept(
        concept="Secreto",
        tx_id="tx-102",
        sender="ana",
        receiver="carlos",
        timestamp="2026-11-27T10:00:00+00:00",
        receiver_rsa_public_pem=users_keys["carlos_keys"]["rsa_public_pem"],
        sender_rsa_public_pem=users_keys["ana_keys"]["rsa_public_pem"],
    )

    with pytest.raises((InvalidTag, ValueError)):
        encryption.decrypt_transfer_concept(
            encrypted_aes_key_hex=enc["enc_aes_key_receiver_hex"],
            aes_nonce_hex=enc["aes_nonce_hex"],
            aes_ciphertext_hex=enc["aes_ciphertext_hex"],
            tx_id="tx-102",
            sender="ana",
            receiver="carlos",
            timestamp="2099-01-01T00:00:00+00:00",  # AAD alterado
            user_rsa_private_pem=users_keys["carlos_keys"]["rsa_private_enc_pem"],
            password=users_keys["carlos_pwd"],
        )


def test_encryption_negative_wrong_password_and_wrong_key(users_keys):
    """
    Prueba negativa:
    1) Contraseña incorrecta al intentar desbloquear la clave privada RSA.
    2) Un tercero (Eva) intenta abrir el sobre digital de Carlos con su propia clave privada.
    """
    enc = encryption.encrypt_transfer_concept(
        concept="Solo para Carlos",
        tx_id="tx-103",
        sender="ana",
        receiver="carlos",
        timestamp="2026-11-27T10:00:00+00:00",
        receiver_rsa_public_pem=users_keys["carlos_keys"]["rsa_public_pem"],
        sender_rsa_public_pem=users_keys["ana_keys"]["rsa_public_pem"],
    )

    # 1) Contraseña incorrecta
    with pytest.raises(ValueError):
        encryption.decrypt_transfer_concept(
            encrypted_aes_key_hex=enc["enc_aes_key_receiver_hex"],
            aes_nonce_hex=enc["aes_nonce_hex"],
            aes_ciphertext_hex=enc["aes_ciphertext_hex"],
            tx_id="tx-103",
            sender="ana",
            receiver="carlos",
            timestamp="2026-11-27T10:00:00+00:00",
            user_rsa_private_pem=users_keys["carlos_keys"]["rsa_private_enc_pem"],
            password="PasswordIncorrecta!",
        )

    # 2) Clave privada de Eva (no autorizada) intentando descifrar el sobre de Carlos
    with pytest.raises(ValueError):
        encryption.decrypt_transfer_concept(
            encrypted_aes_key_hex=enc["enc_aes_key_receiver_hex"],
            aes_nonce_hex=enc["aes_nonce_hex"],
            aes_ciphertext_hex=enc["aes_ciphertext_hex"],
            tx_id="tx-103",
            sender="ana",
            receiver="carlos",
            timestamp="2026-11-27T10:00:00+00:00",
            user_rsa_private_pem=users_keys["eva_keys"]["rsa_private_enc_pem"],
            password=users_keys["eva_pwd"],
        )


# 3. TESTS DE INTEGRIDAD CONTABLE (MAC.PY)

def test_hmac_positive_and_negative_tampering(hmac_key):
    """
    Prueba positiva y negativas de HMAC-SHA256:
    - Datos intactos -> True.
    - Importe alterado (25.50 -> 2500.00) -> False.
    - Etiqueta HMAC alterada -> False.
    - Clave HMAC distinta -> False.
    """
    nonce = mac.generate_tx_nonce()
    tag = mac.generate_settlement_hmac(hmac_key, "tx-200", "ana", "carlos", 25.50, nonce)

    # Positivo
    assert mac.verify_settlement_hmac(hmac_key, "tx-200", "ana", "carlos", 25.50, nonce, tag) is True

    # Negativo 1: Importe manipulado
    assert mac.verify_settlement_hmac(hmac_key, "tx-200", "ana", "carlos", 2500.00, nonce, tag) is False

    # Negativo 2: Etiqueta HMAC manipulada
    fake_tag = tag[:-1] + ("0" if tag[-1] != "0" else "1")
    assert mac.verify_settlement_hmac(hmac_key, "tx-200", "ana", "carlos", 25.50, nonce, fake_tag) is False

    # Negativo 3: Clave HMAC incorrecta
    wrong_key = mac.derive_hmac_key(secrets.token_bytes(32))
    assert mac.verify_settlement_hmac(wrong_key, "tx-200", "ana", "carlos", 25.50, nonce, tag) is False


# 4. TESTS DE FIRMA DIGITAL (SIGNATURES.PY)

def test_ecdsa_signature_positive_and_negative(users_keys):
    """
    Prueba positiva y negativas de firma digital ECDSA (P-256 + SHA-256):
    - Firma legítima de Ana -> True.
    - Importe alterado -> False.
    - Ciphertext alterado -> False.
    - Firma alterada -> False.
    - Verificación con la clave pública de otro usuario (Eva) -> False.
    """
    nonce = mac.generate_tx_nonce()
    ct_hex = "aabbccddeeff00112233445566778899"
    ts = "2026-11-27T10:00:00+00:00"

    sig = signatures.sign_transfer(
        sender_ecdsa_private_pem=users_keys["ana_keys"]["ecdsa_private_enc_pem"],
        password=users_keys["ana_pwd"],
        tx_id="tx-300",
        sender="ana",
        receiver="carlos",
        amount=50.00,
        timestamp=ts,
        tx_nonce=nonce,
        aes_ciphertext_hex=ct_hex,
    )

    ana_pub = users_keys["ana_keys"]["ecdsa_public_pem"]
    eva_pub = users_keys["eva_keys"]["ecdsa_public_pem"]

    # Positivo
    assert signatures.verify_transfer_signature(ana_pub, "tx-300", "ana", "carlos", 50.00, ts, nonce, ct_hex, sig) is True

    # Negativo 1: Importe alterado
    assert signatures.verify_transfer_signature(ana_pub, "tx-300", "ana", "carlos", 5000.00, ts, nonce, ct_hex, sig) is False

    # Negativo 2: Concepto cifrado alterado
    assert signatures.verify_transfer_signature(ana_pub, "tx-300", "ana", "carlos", 50.00, ts, nonce, ct_hex[:-1] + "0", sig) is False

    # Negativo 3: Firma alterada
    fake_sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    assert signatures.verify_transfer_signature(ana_pub, "tx-300", "ana", "carlos", 50.00, ts, nonce, ct_hex, fake_sig) is False

    # Negativo 4: Clave pública equivocada (suplantación de identidad)
    assert signatures.verify_transfer_signature(eva_pub, "tx-300", "ana", "carlos", 50.00, ts, nonce, ct_hex, sig) is False


# 5. TESTS END-TO-END Y REPLAY ATTACK (DATABASE.PY)

def test_replay_attack_rejected_by_database(tmp_path, users_keys, hmac_key):
    """
    Prueba de integración + Ataque de Repetición (Replay Attack):
    1) Crea una BD temporal limpia y registra a Ana y Carlos.
    2) Ejecuta una transferencia válida con un tx_nonce único -> OK y saldos actualizados.
    3) Intenta reenviar EXACTAMENTE la misma transferencia (mismo tx_nonce) -> ValueError.
    """
    test_db = str(tmp_path / "test_cryptopay.json")
    db.init_db(test_db)

    # Registramos usuarios en la BD temporal
    s1, h1 = auth.hash_password(users_keys["ana_pwd"])
    s2, h2 = auth.hash_password(users_keys["carlos_pwd"])
    db.create_user("ana", s1, h1, auth.generate_totp_secret(),
                   users_keys["ana_keys"]["rsa_public_pem"], users_keys["ana_keys"]["rsa_private_enc_pem"],
                   users_keys["ana_keys"]["ecdsa_public_pem"], users_keys["ana_keys"]["ecdsa_private_enc_pem"],
                   initial_balance=100.00, db_path=test_db)
    db.create_user("carlos", s2, h2, auth.generate_totp_secret(),
                   users_keys["carlos_keys"]["rsa_public_pem"], users_keys["carlos_keys"]["rsa_private_enc_pem"],
                   users_keys["carlos_keys"]["ecdsa_public_pem"], users_keys["carlos_keys"]["ecdsa_private_enc_pem"],
                   initial_balance=100.00, db_path=test_db)

    # Preparamos una transferencia completa
    tx_id = "tx-replay-01"
    ts = "2026-11-27T11:00:00+00:00"
    tx_nonce = mac.generate_tx_nonce()

    enc = encryption.encrypt_transfer_concept(
        "Alquiler", tx_id, "ana", "carlos", ts,
        users_keys["carlos_keys"]["rsa_public_pem"], users_keys["ana_keys"]["rsa_public_pem"]
    )
    sig = signatures.sign_transfer(
        users_keys["ana_keys"]["ecdsa_private_enc_pem"], users_keys["ana_pwd"],
        tx_id, "ana", "carlos", 30.00, ts, tx_nonce, enc["aes_ciphertext_hex"]
    )
    tag = mac.generate_settlement_hmac(hmac_key, tx_id, "ana", "carlos", 30.00, tx_nonce)

    # Primer envío (legítimo): debe funcionar y actualizar saldos (70 € y 130 €)
    db.execute_transfer(
        tx_id, "ana", "carlos", 30.00, ts,
        enc["aes_nonce_hex"], enc["aes_ciphertext_hex"],
        enc["enc_aes_key_receiver_hex"], enc["enc_aes_key_sender_hex"],
        sig, tag, tx_nonce, db_path=test_db
    )
    assert db.get_user_by_username("ana", db_path=test_db)["balance"] == 70.00
    assert db.get_user_by_username("carlos", db_path=test_db)["balance"] == 130.00

    # Segundo envío con el MISMO tx_nonce (Replay Attack): debe ser rechazado
    with pytest.raises(ValueError, match="repetición"):
        db.execute_transfer(
            tx_id, "ana", "carlos", 30.00, ts,
            enc["aes_nonce_hex"], enc["aes_ciphertext_hex"],
            enc["enc_aes_key_receiver_hex"], enc["enc_aes_key_sender_hex"],
            sig, tag, tx_nonce, db_path=test_db
        )

    # Comprobamos que los saldos NO se volvieron a modificar tras el ataque
    assert db.get_user_by_username("ana", db_path=test_db)["balance"] == 70.00
    assert db.get_user_by_username("carlos", db_path=test_db)["balance"] == 130.00