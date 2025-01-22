from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import hashlib

def generate_wallet():
    # Gerar chave privada (usando algoritmo ECDSA)
    private_key = ec.generate_private_key(ec.SECP256K1())
    
    # Serializar a chave privada para exportação
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Gerar chave pública
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Criar um endereço a partir da chave pública (hash simplificado)
    address = hashlib.sha256(public_key_bytes).hexdigest()
    
    return {
        "private_key": private_key_bytes.decode('utf-8'),
        "public_key": public_key_bytes.decode('utf-8'),
        "address": address
    }

# Gerar a wallet
wallet = generate_wallet()

# Exibir os dados
print("Chave Privada:")
print(wallet["private_key"])
print("\nChave Pública:")
print(wallet["public_key"])
print("\nEndereço da Wallet:")
print(wallet["address"])
