from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from os import urandom
from db.peer_table import PeerTable
from scripts.shared import t_print
from time import time
import random as r

class Crpyt():
    def __init__(self, db : PeerTable) -> None:
        self.hash_algo = hashes.SHA256
        self.padding_algo = padding.OAEP
        self.rsa_key_size = 2048
        self.sym_key_size = 256
        self.db = db
        self.private_key = rsa.RSAPrivateKey # set type for linting
        self.public_key = rsa.RSAPublicKey
        self.private_key, self.public_key = self.load_host_keys()
        self.identifier = self.db.get_host_identifier()
    
    def load_host_keys(self) -> tuple:
        # host private key stored in public key column of db at record 0 for retrieval
        private_key = self.db.get_host_key() # retrieve PEM string representation
        if not private_key: # If no private key was found
            private_key = self.generate_private_key()
            key_save = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption()) # not encrypting, BAD!
            key_save = key_save.decode('utf-8')
            ident = self._generate_identifier()
            self.db.new_host(ident, key_save, '0.0.0.0', time())
        else: # if private key was in db
            private_key = private_key.encode('utf-8') # encode str returned by DB back into bytes
            private_key = serialization.load_pem_private_key(data=private_key, password=None, backend=None) # de serialise the private key PEM bytes
        public_key = private_key.public_key() # derive the public key
        return (private_key, public_key)
    
    def _generate_identifier(self) -> str:
        for i in range(0,5): # would use a while loop but it makes me nervous, 5 tries should be enough?
            identifier = r.randbytes(16)
            identifier = identifier.hex()
            if not self.db.check_if_identifier_exists(identifier): # check that the identifier isnt already in use
                return identifier
    
    def public_key_to_bytes(self, public_key : rsa.RSAPublicKey) -> bytes:
        bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo,)
        return bytes   
    
    def public_key_from_bytes(self, bytes : bytes):
        public_key = serialization.load_pem_public_key(bytes)
        return public_key

    def private_key_to_bytes(self, private_key : rsa.RSAPrivateKey) -> bytes:
        bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.PKCS8,
                                        encryption_algorithm=serialization.NoEncryption())
        return bytes
    
    def private_key_from_bytes(self, bytes : bytes):
        private_key = serialization.load_pem_private_key(data=bytes, password=None, backend=None)
        return private_key
    
    def generate_private_key(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(65537, self.rsa_key_size)
    
    def rsa_decrypt(self, ciphertext : bytes) -> str:
        plaintext = self.private_key.decrypt(ciphertext=ciphertext,
                                             padding=self.padding_algo(
                                                mgf=padding.MGF1(algorithm=self.hash_algo()),
                                                algorithm=self.hash_algo(),
                                                label=None))
        plaintext.decode('utf-8')
        return plaintext
    
    def rsa_encrypt(self, plaintext : bytes, public_key : rsa.RSAPublicKey = None) -> bytes:
        if not public_key: # if no public key passed, use host
            public_key = self.public_key
        if isinstance(plaintext, str):
            plaintext.encode('utf-8')
        ciphertext = public_key.encrypt(plaintext=plaintext,
                                            padding=self.padding_algo(
                                                mgf=padding.MGF1(algorithm=self.hash_algo()),
                                                algorithm=self.hash_algo(),
                                                label=None))
        return ciphertext
    
    def rsa_generate_signature(self, message : bytes, private_key : rsa.RSAPrivateKey) -> bytes:
        signature = private_key.sign(data=message,
                                     padding=padding.PSS(
                                        mgf=padding.MGF1(self.hash_algo()),
                                        salt_length=padding.PSS.MAX_LENGTH),
                                     algorithm=self.hash_algo())
        return signature
        
    def rsa_verify_signature(self, signature : bytes, data : bytes, public_key : rsa.RSAPublicKey) -> bool:
        try:
            public_key.verify(signature=signature,
                                data=data,
                                padding=padding.PSS(
                                    mgf=padding.MGF1(self.hash_algo()),
                                    salt_length=padding.PSS.MAX_LENGTH),
                                algorithm=self.hash_algo())
            return True
        except InvalidSignature:
            return False
        
        
    def generate_sym_key(self) -> bytes:
        return urandom(int(self.sym_key_size/8))
    
    def sym_encrypt(self, plaintext : bytes, sym_key : bytes) -> bytes:
        init_vector = urandom(16)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = Cipher(algorithm=algorithms.AES(sym_key), mode=modes.GCM(init_vector))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext
    
    def sym_decrypt(self, ciphertext : bytes, sym_key : bytes, init_vector : bytes) -> str:
        cipher = Cipher(algorithm=algorithms.AES(sym_key), mode=modes.GCM(init_vector))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = plaintext.decode('utf-8')
        return plaintext
