from Decryption import RSACipher_Decrypt
import os
import sys
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

keySize = 32
IVSize = 16

def Myencrypt(plaintext):
    iv = os.urandom(IVSize)
    key = os.urandom(keySize)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag, key)

 
def RSAEnc(plaintext, RSA_PublicKey_filepath):

    ciphertext, tag, iv, key = Myencrypt(msg)

    with open(RSA_PublicKey_filepath, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
#       password,
        backend=default_backend()
    )

        key_file.close()
    
    RSACipher = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    tag = base64.b64encode(tag).decode('utf-8')
    iv = base64.b64encode(iv).decode('utf-8')
    RSACipher = base64.b64encode(RSACipher).decode('utf-8')
 

    return (ciphertext_base64, tag, iv, RSACipher)


if '--e' in sys.argv and '--rsakeypath' in sys.argv and '--prvkeypath':
    RSAPubKeyPath = sys.argv[sys.argv.index('--rsakeypath') + 1]
    RSAPrvKeyPath = sys.argv[sys.argv.index('--prvkeypath')+1]
    msg = [sys.argv.index('--e') + 1]
    ciphertext, tag, iv, RSACipher = RSAEnc(msg, RSAPubKeyPath)
    RSACipher_Decrypt(ciphertext, tag, iv, RSACipher, RSAPrvKeyPath)
    