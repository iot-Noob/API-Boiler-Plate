import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from App.GetEnvDate import ivs, key, set_keys
from App.LoggingInit import *
from fastapi import HTTPException
class AES_Encrypt:
    def __init__(self):
        # Initialize key and IV
        self.gkey = base64.b64decode(key) if key else os.urandom(32)  # 256-bit key for AES
        self.giv = base64.b64decode(ivs) if ivs else os.urandom(16)  # 128-bit IV for AES
        
        if not key or not ivs:
            self.gkey_b64 = base64.b64encode(self.gkey).decode('utf-8')
            self.giv_b64 = base64.b64encode(self.giv).decode('utf-8')
            try:
                set_keys("AES_KEY", self.gkey_b64)
                set_keys("AES_IV", self.giv_b64)
            except Exception as e:
                print(f"Error setting crypto AES keys data due to {e}")
                logging.error(f"Error setting crypto AES keys data due to {e}")

    def encrypt(self, mesg: str) -> bytes:
        try:
            cipher = Cipher(algorithms.AES(self.gkey), modes.CBC(self.giv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Encode the message as bytes, then pad it using cryptography's padding
            mesg_bytes = mesg.encode('utf-8')
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_mesg = padder.update(mesg_bytes) + padder.finalize()
            
            ct = encryptor.update(padded_mesg) + encryptor.finalize()
            return base64.b64encode(ct).decode('utf-8')
        except Exception as e:
            print(f"Error encrypt due to {e}")
            logging.error(f"Error encrypt to AES due to {e}")
            return HTTPException(500,f"Error AES Encrypt  due to {e}")

    def decrypt(self, ct: bytes) -> str:
        cipher = Cipher(algorithms.AES(self.gkey), modes.CBC(self.giv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            ct=base64.b64decode(ct)
            decrypted_padded_mesg = decryptor.update(ct) + decryptor.finalize()
            
            # Remove padding using cryptography's padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_mesg = unpadder.update(decrypted_padded_mesg) + unpadder.finalize()
            
            return decrypted_mesg.decode('utf-8')
        
        except ValueError as e:
            print(f"Decryption failed: {e}")
            logging.error(f"Error decrypt to AES due to {e}")
            return HTTPException(500,f"Error AES Decrypt  due to {e}")
    
    def change_key(self):
        # Initialize key and IV
        self.gkey = os.urandom(32)  # 256-bit key for AES
        self.giv =  os.urandom(16)  # 128-bit IV for AES
        
      
        self.gkey_b64 = base64.b64encode(self.gkey).decode('utf-8')
        self.giv_b64 = base64.b64encode(self.giv).decode('utf-8')
        try:
            set_keys("AES_KEY", self.gkey_b64)
            set_keys("AES_IV", self.giv_b64)
        except Exception as e:
                print(f"Error setting crypto AES keys data due to {e}")
                logging.error(f"Error setting crypto AES keys data due to {e}")
 
 
 