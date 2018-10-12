import sys
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

#Obtaining information about JSON from command line
if '--d' in sys.argv and 'RSAcipher:' in sys.argv:
    RSAciphertxt = sys.argv[sys.argv.index('RSAcipher:')+1]
    AESciphertxt = sys.argv[sys.argv.index('AEScipher:')+1]


#Retrieving private key
# with open("RSA2048 KeyPair\privkey.ppk", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#         backend = default_backend()
#     )