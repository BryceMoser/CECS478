import sys
import os 
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)


#RSAPrvKeyPath = sys.argv[sys.argv.index('--prvkeypath') + 1]
def Mydecrypt(ciphertext, tag, iv, key):
  #Decrypts the ciphertext using the tag, iv and key
  decryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv, tag),
      backend=default_backend()
  ).decryptor()
  #Returns the decrypted value
  return decryptor.update(ciphertext) + decryptor.finalize()

def RSACipher_Decrypt (cipherTxt, tag, IV, rsaCipher, RSAPrvKeyPath):

    cipherTxt = base64.b64decode(cipherTxt)
    tag = base64.b64decode(tag)
    IV = base64.b64decode(IV)
    rsaCipher = base64.b64decode(rsaCipher)


    #Serializing Private Key
    with open(RSAPrvKeyPath, 'rb') as privKeyFile:
        privKey = serialization.load_pem_private_key(privKeyFile.read(), password=None, backend=default_backend())
    privKeyFile.close()

    #Determining AES from RSACipher

    #rsaCipher = base64.b64decode(rsaCipher)
    AESKey = privKey.decrypt(
        rsaCipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
      )
    
    plaintext = Mydecrypt(cipherTxt, tag, IV, AESKey)
    plaintext = plaintext.decode('ascii')
    return plaintext






