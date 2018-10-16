import sys
import json
import os 
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

#Gathering encryption data from JSON
 # AES(MSG) -> Key, IV Ciphertext, tag -> RSA.E(Key, publicKey) -> RSA.D(Key, privateKey)



def RSACipher_Decrypt (jsonFile, RSAPrvKeyPath):
    
    #Unpacking JSON
    cipherTxt = base64.b64decode(jsonFile['ciphertext_base64'])
    tag = base64.b64decode(jsonFile['tag'])
    IV = base64.b64decode(jsonFile['iv'])
    rsaCipher = base64.b64decode(jsonFile['RSACipher'])

    #Serializing Private Key
    with open(RSAPrvKeyPath, 'rb') as privKeyFile:
        privKey = serialization.load_pem_private_key(privKeyFile.read(), password=None, backend=default_backend())
    privKeyFile.close()

    #Determining AES from RSACipher
    AESKey = privKey.decrypt(
        rsaCipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
      )

    #Decrypting message using private key
    plaintext = privKey.decrypt(
        cipherTxt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #If decryption works print out message
    print(plaintext)



if '--d' in sys.argv and '--rsaprivkey' in sys.argv:
    with open(sys.argv[sys.argv.index('--d')+1]) as enc:
        json_file = json.load(enc)
    RSAPrvKeyPath = sys.argv[sys.argv.index('--rsaprivkey') + 1]
    RSACipher_Decrypt(json_file, RSAPrvKeyPath)

