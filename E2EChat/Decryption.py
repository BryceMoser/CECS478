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
    cipherTxt = jsonFile['ciphertext_base64']
    tag = jsonFile['tag']
    IV = jsonFile['iv']
    rsaCipher = jsonFile['RSACipher']
    
    #Serializing Private Key
    with open(RSAPrvKeyPath, 'rb') as privKeyPath:
        privateKey = serialization.load_pem_private_key(
            privKeyPath.read(),
            password=None,
            backend=default_backend
        )

    #Determining AES from RSACipher
    #Make sure your key is loaded correctly
 
        #Make sure this runs without errors
        # AESKey = privateKey.decrypt(
        # rsaCipher,
        # padding.OAEP(
        #     mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #     algorithm=hashes.SHA256(),
        #     label=None
        # ))
        # print(AESKey)

#     #Decrypting message using private key
#     rsadecrypt = Cipher(
#     algorithms.AES(prvKey),
#     modes.GCM(IV, tag),
#     backend=default_backend
#     ).decryptor()
#     decryptPT = rsadecrypt.update(cipherTxt)+rsadecrypt.finalize()
#     #If decryption works print out message


if '--d' in sys.argv and '--rsaprvkey' in sys.argv:
    with open(sys.argv[sys.argv.index('--d')+1]) as enc:
        json_file = json.load(enc)
    RSAPrvKeyPath = sys.argv[sys.argv.index('--rsaprvkey') + 1]

    RSACipher_Decrypt(json_file, RSAPrvKeyPath)

