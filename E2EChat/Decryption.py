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
#Make sure your json is correctly unpacked
def unpackJSON (jsonFile):
    for d in jsonFile:
        cipherTxt = d['ciphertext_base64']
        tag = d['tag']
        IV = d['iv']
        rsaCipher = d['RSACipher'] #            AES(MSG) -> Key, IV Ciphertext, tag -> RSA.E(Key, publicKey) -> RSA.D(Key, privateKey)
    return (cipherTxt, tag, IV, rsaCipher)


def RSACipher_Decrypt (jfile):
    cipherTxt, tag, IV, rsaCipher = unpackJSON(jfile)
    
    #Determining AES from RSACipher
    #Make sure your key is loaded correctly
    with open("privateKey" "rb") as privKey:
        #Make sure this runs without errors
        AESKey = privKey.decrypt(
        rsaCipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

    #Decrypting message using private key
    rsadecrypt = Cipher(
    algorithms.AES(prvKey),
    modes.GCM(IV, tag),
    backend=default_backend
    ).decryptor()
    decryptPT = rsadecrypt.update(cipherTxt)+rsadecrypt.finalize()
    #If decryption works print out message


if '--d' in sys.argv and '--rsakeypath' in sys.argv:
    with open(sys.argv[sys.argv.index('--d')+1]) as enc:
        json_file = json.loads(enc)
print(RSACipher_Decrypt(json_file))

