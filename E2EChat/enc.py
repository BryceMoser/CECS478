import os
import sys
import json
#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import serialization

if '--e' in sys.argv and '--rsakeypath' in sys.argv:
    RSAPubKeyPath = sys.argv[sys.argv.index('--rsakeypath') + 1]
    print("\nYour public key path: ", RSAPubKeyPath)