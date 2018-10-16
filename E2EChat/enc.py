import os
import sys
import json
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

def Myencrypt(plaintext, key):
    iv = os.urandom(IVSize)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)


def MyfileEncrypt(msgPath):
    key = os.urandom(keySize)
    file_name, file_extension = os.path.splitext(msgPath)

    with open(msgPath, "rb") as binary_file:
        data = binary_file.read()
        iv, ciphertext, tag = Myencrypt(
            data,
            key
        )
        return (ciphertext, tag, iv, key, file_extension)
 
def RSAEnc(filepath, RSA_PublicKey_filepath):
    file_name = os.path.splitext(filepath)[0]

    ciphertext, tag, iv, key, file_extension = MyfileEncrypt(msgPath)

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


    data = {}
    data['ciphertext_base64'] = base64.b64encode(ciphertext).decode('utf-8')
    data['tag'] = base64.b64encode(tag).decode('utf-8')
    data['iv'] = base64.b64encode(iv).decode('utf-8')
    data['RSACipher'] = base64.b64encode(RSACipher).decode('utf-8')
    data['file_extension'] = file_extension

    output_filename = file_name + '.rsa'

    outfile = open(output_filename, 'w')
    outfile.write(json.dumps(data))
    outfile.close()
    return (output_filename)


if '--e' in sys.argv and '--rsakeypath' in sys.argv:
    RSAPubKeyPath = sys.argv[sys.argv.index('--rsakeypath') + 1]
    msgPath = sys.argv[sys.argv.index('--e') + 1]
    RSAEnc(msgPath, RSAPubKeyPath)