import random
import os

import packages as pkg
pkg.install('blowfish') # pip install blowfish
import blowfish

fileName = 'encryption.key'
privateKey = None

def generateKey():
    privateKey = random.randbytes(55) # key must be between 4 and 56 bytes long (added and removed 1 of margin to be sure)
    with open(fileName, 'wb') as f:
        f.write(privateKey)

def readKey():
    with open(fileName, 'rb') as f:
        privateKey = f.read()

def encrypt(data):
    cipher = blowfish.Cipher(privateKey)
    return b"".join(cipher.encrypt_ecb_cts(data))

def decrypt(data):
    cipher = blowfish.Cipher(privateKey)
    return b"".join(cipher.decrypt_ecb_cts(data))

if os.path.isfile(fileName):
    readKey()
else:
    generateKey()