#Built on Python 2.7.6
#Version 1.0

#Internal modules
from base64 import b64decode
from base64 import b64encode
from datetime import datetime

#External modules

#pycrypto (Version: 2.6.1)
#https://www.dlitz.net/software/pycrypto/
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as PKCS1_OAEP_Cipher
from Crypto.Signature import PKCS1_v1_5

class SimpleRSADigitalSigner():

	#Constructor
	def __init__(self, privateKeyFile, publicKeyFile):
		self.privateKeyFile = privateKeyFile
		self.publicKeyFile = publicKeyFile
		self.loadKeys()
	
	#Load the keys
	def loadKeys(self):
		#Load the private RSA key.
		self.privateKey = RSA.importKey(open(self.privateKeyFile, 'r'))
		
		#Load the public RSA key.
		self.publicKey = RSA.importKey(open(self.publicKeyFile, 'r'))
	
	#Encrypts the plaintext
	def encrypt(self, plaintext, encoded=None):
		pkcs_cipher = PKCS1_OAEP_Cipher.new(self.publicKey)
		encrypted = pkcs_cipher.encrypt(plaintext)
		if encoded is None:
			return encrypted
		else:
			return b64encode(encrypted)
	
	#Decrypts the ciphertext
	def decrypt(self, ciphertext, encoded=None):
		if encoded is not None:
			ciphertext = b64decode(ciphertext)
		
		pkcs_cipher = PKCS1_OAEP_Cipher.new(self.privateKey);
		return pkcs_cipher.decrypt(ciphertext)

	#Sign the plaintext message
	def sign(self, plaintext, hash):
		signer = PKCS1_v1_5.new(self.privateKey)
		hash = hash.new()
		hash.update(plaintext)
		return b64encode(signer.sign(hash))
	
	#Verify the signature
	def verify(self, plaintext, signature, hash):
		signer = PKCS1_v1_5.new(self.publicKey)
		hash = hash.new()
		hash.update(plaintext)
		return signer.verify(hash, b64decode(signature))
	
	@staticmethod
	def get2K1DEpoch():
		return long((datetime.utcnow() - datetime(2010, 1, 1, 0, 0, 0)).total_seconds())
