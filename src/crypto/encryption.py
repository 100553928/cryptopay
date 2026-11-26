import secrets
from typing import Dict, Union
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag

# Constantes
AES_KEY_BITS = 256
GCM_NONCE_LENGTH = 12

# Estas funciones devuelven el objeto para llamar directamente a .encrypt(...)
# o para envolver la clave AES o a .decrypt(...) para abrir el sobre digital.
def load_private_key(encrypted_pem: str, password: str
                     ) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    if not password:
        raise ValueError("Se requiere la contraseña para desbloquear la clave privada")
    try:
        # La libreria cryptography necesita los datos en bytes
        private_key = serialization.load_pem_private_key(
            encrypted_pem.encode("utf-8"), # Convierte el bloque PEM a bytes
            password = password.encode("utf-8") # Convierte la contraseña del usuario a bytes
        )
        return private_key
    except (ValueError, TypeError) as exc:
        raise ValueError("Contraseña incorrecta o clave privada PEM corrupta.") from exc

def load_public_key(public_pem:str
                    ) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
    try:
        # Convierte la clave publica en bytes
        return serialization.load_pem_public_key(public_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise ValueError("Formato de clave pública PEM inválido")

def encrypt_transfer_concept(
    concept: str,
    tx_id: str,
    sender: str,
    receiver: str,
    timestamp: str,
    receiver_rsa_public_pem: str,
    sender_rsa_public_pem: str,
) -> Dict[str, str]:
    # Calculamos una clave AES de 256 bits
    aes_key = AESGCM.generate_key(bit_length=256)
    
    # Calculamos un nonce de 12 bytes
    nonce = secrets.token_bytes(12)
    
    # Unimos los metadatos en una sola cadena
    aad = f"{tx_id}|{sender}|{receiver}|{timestamp}".encode("utf-8")
    
    # Instanciamos el motor GCM
    aesgcm = AESGCM(aes_key)
    
    # Ciframos los bytes del concepto y los ligamos a la cadena de aad. Ahora si alguien 
    # cambia algún metadato público lo sabremos y ocultamos el concepto de la transferencia
    ciphertext = aesgcm.encrypt(nonce, concept.encode("utf-8"), aad)
    
    # Ahora hay que cifrar aes_key (por duplicado con la clave RSA publica de emisor y receptor), 
    # para que solo el receptor y el emisor puedan acceder al concepto cifrado y puedan validar 
    # los metadatos
    
    # Cargamos en RAM el candado del receptor y el del emisor.
    receiver_public_key = load_public_key(receiver_rsa_public_pem)
    sender_public_key = load_public_key(sender_rsa_public_pem)
    
    # Aplicamos un esquema de relleno probabilístico OAEP para envolver y mezclar la clave AES
    # antes de aplicar RSA, internamente se usa SHA256
    oaep_padding = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                                algorithm=hashes.SHA256(), label=None)
    
    # Ciframos la clave AES para el receptor y el emisor mediante RSA-2048
    enc_aes_receiver = receiver_public_key.encrypt(aes_key, oaep_padding)
    enc_aes_sender = sender_public_key.encrypt(aes_key, oaep_padding)
    
    return {
    "aes_nonce_hex": nonce.hex(),
    "aes_ciphertext_hex": ciphertext.hex(),
    "enc_aes_key_receiver_hex": enc_aes_receiver.hex(),
    "enc_aes_key_sender_hex": enc_aes_sender.hex(),
}
    
def decrypt_transfer_concept(
    encrypted_aes_key_hex: str,
    aes_nonce_hex: str,
    aes_ciphertext_hex: str,
    tx_id: str,
    sender: str,
    receiver: str,
    timestamp: str,
    user_rsa_private_pem: str,
    password: str,
) -> str:
    
    # Activamos la clave privada del usuario en la memoria RAM
    private_key = load_private_key(user_rsa_private_pem, password)
    
    # Convertimos los textos hexadecimales en bytes
    enc_aes_key = bytes.fromhex(encrypted_aes_key_hex)
    nonce = bytes.fromhex(aes_nonce_hex)
    ciphertext = bytes.fromhex(aes_ciphertext_hex)
    
    # Volviendo a aplicar OAEP (con SHA256) revertimos la operación y con nuestra clave privada obtenemos aes_key
    oaep_padding = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    aes_key = private_key.decrypt(enc_aes_key, oaep_padding)
    
    # Volvemos a montar aad para comprobar que coincide byte a byte 
    # con el aad que generamos anteriormente
    aad = f"{tx_id}|{sender}|{receiver}|{timestamp}".encode("utf-8")
    
    # Instanciamos el motor GCM
    aesgcm = AESGCM(aes_key)

    # Desciframos el concepto, comprobando que aad coincide con el aad ligado al texto cifrado.
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)

    # Si todo es correcto se devuelve el concepto original en claro.
    return plaintext_bytes.decode("utf-8")