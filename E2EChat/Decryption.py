import sys
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

#Generates an RSA object with the loaded .pem private key
with open('RSA2048 KeyPair\privkey.ppk') as key_file:
    prvK = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend
    )

#Parsing information about JSON from command line:
if '--d' in sys.argv:
    with open(sys.argv[sys.argv.index('--d')+1]) as enc:
        json_data = json.loads(enc)
        for p in json_data['Message']:
            rsaCipher = p['rsa_ciphertext']


    # print('RSA Ciphertext'+p['rsa_ciphertxt'])
    # print('AES Ciphertext'+p['aes_ciphertxt'])
    # print('HMAC tag'+p['htag'])
    # print('Key path'+p['path'])