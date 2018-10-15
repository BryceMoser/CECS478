from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

with open("D:\\College Classes\\Fall 2018\CECS478\\RSA2048 KeyPair\\rsaPrivKey.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
pubKey = key.public_key()
with open("D:\\College Classes\\Fall 2018\CECS478\\RSA2048 KeyPair\\rsaPubKey.pem", "wb") as f:
    f.write(pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))