"""
encryption.py

Laboratorio de Cifrado y Manejo de Credenciales

En este módulo deberás implementar:

- Descifrado AES (MODE_EAX)
- Hash de contraseña con salt usando PBKDF2-HMAC-SHA256
- Verificación de contraseña usando el mismo salt

NO modificar la función encrypt_aes().
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import hmac

# ==========================================================
# AES-GCM (requiere pip install pycryptodome)
# ==========================================================

def encrypt_aes(texto, clave):
    """
    Cifra un texto usando AES en modo EAX.

    Retorna:
        texto_cifrado_hex
        nonce_hex
        tag_hex
    """

    texto_bytes = texto.encode()

    cipher = AES.new(clave, AES.MODE_EAX)

    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)

    return (
        texto_cifrado.hex(),
        nonce.hex(),
        tag.hex()
    )




def decrypt_aes(texto_cifrado_str, nonce_hex, tag_hex, clave):

    texto_cifrado = bytes.fromhex(texto_cifrado_str)
    nonce = bytes.fromhex(nonce_hex)
    tag = bytes.fromhex(tag_hex)

    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)
    
    try:

        datos_descifrados = cipher.decrypt_and_verify(texto_cifrado, tag)
        
        return datos_descifrados.decode()
        
    except ValueError:

        print("Error: La integridad de los datos no pudo ser verificada.")
        return None

# ==========================================================
# PASSWORD HASHING (PBKDF2 - SHA256)
# ==========================================================


def hash_password(password):

    iterations = 200000
    dklen = 32 
    
    salt = os.urandom(16)

    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt, 
        iterations, 
        dklen=dklen
    )

    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": hash_bytes.hex()
    }



def verify_password(password, stored_data):

    salt_hex = stored_data.get("salt")
    iterations = stored_data.get("iterations")
    hash_original_hex = stored_data.get("hash")

    salt_bytes = bytes.fromhex(salt_hex)

    hash_nuevo = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt_bytes,
        iterations,
        dklen=32
    )

    return hmac.compare_digest(hash_nuevo.hex(), hash_original_hex)



if __name__ == "__main__":

    print("=== PRUEBA AES ===")

    texto = "Hola Mundo"
    clave = get_random_bytes(16)

    texto_cifrado, nonce, tag = encrypt_aes(texto, clave)

    print("Texto cifrado:", texto_cifrado)
    print("Nonce:", nonce)
    print("Tag:", tag)

    # Cuando implementen decrypt_aes, esto debe funcionar
    texto_descifrado = decrypt_aes(texto_cifrado, nonce, tag, clave)
    print("Texto descifrado:", texto_descifrado)


    print("\n=== PRUEBA HASH ===")

    password = "Password123!"

    # Cuando implementen hash_password:
    pwd_data = hash_password(password)
    print("Hash generado:", pwd_data)

    # Cuando implementen verify_password:
    print("Verificación correcta:",
           verify_password("Password123!", pwd_data))