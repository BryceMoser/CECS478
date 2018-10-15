import sys
import json
import os 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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


if '--d' in sys.argv and '--rsakeypath' in sys.argv:
    with open(sys.argv[sys.argv.index('--d')+1]) as enc:
        json_file = json.loads(enc)
cipherTxt, tag, IV, rsaCipher = unpackJSON(json_file)

pubKey = sys.argv[sys.argv.index('--rsakeypath') + 1]
decryptor = Cipher(
algorithms.AES(pubKey),
modes.GCM(IV, tag),
backend=default_backend
).decryptor()
