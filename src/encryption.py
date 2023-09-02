import random
import os

import packages as pkg
pkg.install('blowfish') # pip install blowfish
import blowfish

class Encryption:
    keyFile = 'data/encryption.key'
    privateKey = None
    
    def __init__(self, keyFile=keyFile):
        self.keyFile = keyFile
        if os.path.isfile(keyFile):
            self.readKey()
        else:
            self.generateKey()

    def generateKey(self):
        self.privateKey = random.randbytes(55) # key must be between 4 and 56 bytes long (added and removed 1 of margin to be sure)
        with open(self.keyFile, 'wb') as f:
            f.write(self.privateKey)

    def readKey(self):
        with open(self.keyFile, 'rb') as f:
            self.privateKey = f.read()

    def encrypt(self, data):
        cipher = blowfish.Cipher(self.privateKey)
        return b"".join(cipher.encrypt_ecb_cts(data))

    def decrypt(self, data):
        cipher = blowfish.Cipher(self.privateKey)
        return b"".join(cipher.decrypt_ecb_cts(data))
    
    def encryptFile(self, taretFile, data):
        data = data.encode('utf-8')
        with open(taretFile, 'wb') as f:
            f.write(self.encrypt(data))

    def decryptFile(self, taretFile):
        if os.path.isfile(taretFile):
            with open(taretFile, 'rb') as f:
                return self.decrypt(f.read()).decode('utf-8')
        else:
            return None
