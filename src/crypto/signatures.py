from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def load_signing_private_key(encrypted_pem: str, password:str) -> ec.EllipticCurvePrivateKey:
    if not password:
        raise ValueError("Se requiere la contraseña para desbloquear la clave privada")
    try:
        private_key = serialization.load_pem_private_key(
            # La libreria cryptography necesita los datos en bytes
            encrypted_pem.encode("utf-8"), # Convierte el bloque PEM a bytes
            password = password.encode("utf-8") # Convierte la contraseña del usuario a bytes
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Contraseña incorrecta o clave privada PEM corrupta")

    # Validamos que la clave este en formato ECDSA
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("La clave privada no es una clave ECDSA")

    return private_key

def load_public_key(public_pem:str) -> ec.EllipticCurvePublicKey:
    try:
        # Convierte la clave publica en bytes
        public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    except(ValueError, TypeError) as exc:
        raise ValueError("Formato de clave pública PEM inválido")
    
    # Validamos que la clave este en formato ECDSA
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("La clave pública no es una clave ECDSA")
    
    return public_key

# Con esta función convertimos todos los metadatos de la transferencia en un secuencia exacta sobre la que 
# calcularemos la firma y se verifique siempre sobre los mismos metadatos (incluido el nonce y el 
# concepto cifrado)
def _build_signature_payload(
    tx_id: str, 
    sender: str, 
    receiver: str, 
    amount: float, 
    timestamp: str, 
    tx_nonce: str, 
    aes_ciphertext_hex: str):
    
    canonical_str = (
        f"{tx_id}|{sender}|{receiver}|{float(amount):.2f}|"
        f"{timestamp}|{tx_nonce}|{aes_ciphertext_hex}"
    )
    return canonical_str.encode("utf-8")

# Esta funcion es genera la firma digital ECDSA-SHA256 del emisor y
# la devuelve en hexadecimal
def sign_transfer(
    sender_ecdsa_private_pem: str, 
    password: str, 
    tx_id: str, 
    sender: str, 
    receiver: str, 
    amount: float, 
    timestamp: str, 
    tx_nonce: str, 
    aes_ciphertext_hex: str) -> str:
    
    # Desbloqueamos la clave privada ECDSA del emisor en memoria RAM
    private_key =  load_signing_private_key(sender_ecdsa_private_pem, password)
    
    # Ejecutamos la funcion que une todos los campos de transferencia
    payload = _build_signature_payload(tx_id, sender, receiver, 
                                                 amount, timestamp, tx_nonce, aes_ciphertext_hex) 
    # Firmamos el resumen SHA-256 del payload con ECDSA
    signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    
    return signature.hex()

# En esta funcion nos aseguramos de que la firma sea valida y que no se haya manipulado ningun dato
def verify_transfer_signature(
    sender_ecdsa_public_pem: str,
    tx_id: str,
    sender: str,
    receiver: str,
    amount: float,
    timestamp: str,
    tx_nonce: str,
    aes_ciphertext_hex: str,
    signature_hex: str,
) -> bool:
    
    try:
        # Desbloqueamos la clave publica ECDSA del emisor en memoria RAM
        public_key = load_public_key(sender_ecdsa_public_pem)
        
        # Traducimos a bytes la firma hexadecimal calculada en la funcion "sign_transfer"
        expected_signature = bytes.fromhex(signature_hex)
        
        # Volvemos a unir todos los campos de transferencia
        payload = _build_signature_payload(tx_id, sender, receiver, 
                                                 amount, timestamp, tx_nonce, aes_ciphertext_hex) 
        
        # Verificamos la firma ECDSA-SHA256
        public_key.verify(expected_signature, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False