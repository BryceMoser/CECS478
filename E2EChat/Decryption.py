import sys
import json
import os 
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

#Gathering encryption data from JSON
def unpackJSON (jsonFile):
    for d in jsonFile:
        cipherTxt = d['ciphertext_base64']
        tag = d['tag']
        IV = d['iv']
        rsaCipher = d['RSACipher']
    return (cipherTxt, tag, IV, rsaCipher)


def RSACipher_Decrypt (jfile):
    cipherTxt, tag, IV, rsaCipher = unpackJSON(jfile)
    
    #Determining AES from RSACipher
    decodedCipher = base64.b64decode(rsaCipher)
    keysDecrypted = rsaCipher.decrypt(decodedCipher, None)
    decodedAES = base64.b64decode(keysDecrypted)
    aesKey = decodedAES[:32]

    #Load in Private Key
    with open ("E2EChat\RSA2048 KeyPair\rsaPrivKey.pem", "rb") as prvkeyfile:
        prvKey = serialization.load_pem_private_key(
            prvkeyfile.read(),
            password=None,
            backend=default_backend
        )
    #Decrypting message using private key
    rsadecrypt = Cipher(
    algorithms.AES(prvKey),
    modes.GCM(IV, tag),
    backend=default_backend
    ).decryptor()
    decryptPT = rsadecrypt.update(cipherTxt)+rsadecrypt.finalize()

    #Checking to make sure Encryption with public key on plaintext yeilds similar results to JSON
    with open('E2EChat\RSA2048 KeyPair\rsaPubKey.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    encryptor = Cipher(
        algorithms.AES(public_key),
        modes.GCM(IV),
        backend=default_backend()
    ).encryptor()
    cipherText = encryptor.update(decryptPT) + encryptor.finalize()


    #Should flag is 
    if cipherText != cipherTxt:
        return print('Unsuccessful')
        
    return decryptPT



if '--d' in sys.argv and '--rsakeypath' in sys.argv:
    with open(sys.argv[sys.argv.index('--d')+1]) as enc:
        json_file = json.loads(enc)
print(RSACipher_Decrypt(json_file))

