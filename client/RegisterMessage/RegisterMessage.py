#Built on Python 2.7.6
#Version 1.0

#Internal modules
import sys
import json
import time
import threading
from datetime import datetime

#External modules
#http://docs.python-requests.org/en/latest/
import requests

#pycrypto (Version: 2.6.1)
#https://www.dlitz.net/software/pycrypto/
from Crypto.Hash import MD5

#SimpleRSADigitalSigner (Version: 1.0.0)
from SimpleRSADigitalSigning import SimpleRSADigitalSigner

class RegisterMessage(threading.Thread):

	#Constructor...
	def __init__(self, websiteName, websiteUrl, constructMessageLambda, privateKey, publicKey, hashAlgorithm=None, sleepTime=None):
		threading.Thread.__init__(self)
		self.websiteUrl = websiteUrl
		self.websiteName = websiteName
		#self.message = message
		self.constructMessageLambda = constructMessageLambda
		self.privateKey = privateKey
		self.publicKey = publicKey
		self.isAlive = True
		
		#Assign the sleepTime or default to 300 seconds if one is not provided.
		if sleepTime is None:
			self.sleepTime = 300
		else:
			self.sleepTime = sleepTime
		
		#Assign the hashAlgorithm or default to MD5 if one is not provided.
		if hashAlgorithm is None:
			self.hashAlgorithm = MD5.new()
		else:
			self.hashAlgorithm = hashAlgorithm
		
		#Create a thread condition to improve thread handling.
		self.condition = threading.Condition()

	#Run method invoked when the thread starts.
	def run(self):
		print('>>Beginning to register for site {0}\n').format(self.websiteUrl)
		self.condition.acquire()
		while self.isAlive:
			try:
				if self.registerMessage():
					self.condition.wait(self.sleepTime)
				else:
					self.isAlive = False
			except:
				e = sys.exc_info()
				print(str(e[0]) + '\r\n' + str(e[1]))
				self.isAlive = False
		self.condition.release()
		print('>>Registration for site {0} has stopped.\n').format(self.websiteUrl)

	#Stops the threads internal loop.
	def stop(self):
		print('>>>>Requesting Stop.\n')
		self.isAlive = False
		try:
			self.condition.acquire()
			self.condition.notifyAll()
			self.condition.release()
		except:
			e = sys.exc_info()
			print(str(e[0]) + '\r\n' + str(e[1]))

	#Perform the actual register logic.
	def registerMessage(self):

		#Construct the message.
		now = datetime.now()
		message = self.constructMessageLambda(now)

		simpleSigning = SimpleRSADigitalSigner(self.privateKey,self.publicKey)

		cipherText = simpleSigning.encrypt(message, True)
		signature = simpleSigning.sign(message, self.hashAlgorithm)
		requestBody = '{Payload:\'' + cipherText + '\',Signature:\'' + signature + '\'}'
		
		#Attempt to post the registration message to the API.
		try:
			headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'register-message-client'}
			r = requests.post(self.websiteUrl, headers=headers, data=requestBody)
			
			#Relay the posted information to our console.
			print('>>>>Request Posted at [{0}]: {1}\n').format(now, requestBody)
			
			#Throw an exception for status that are not 200.
			r.raise_for_status()

			#r.status_code
			
			responseObject = json.loads(r.text)
			payload = responseObject.get('Payload','')
			signature = responseObject.get('Signature','')
			
			responsePlainTextMessage = simpleSigning.decrypt(payload, True)
			if (simpleSigning.verify(responsePlainTextMessage, signature, self.hashAlgorithm)):
				print('Response: {0}\n').format(responsePlainTextMessage)
			else:
				print('No Response')
			
		except:
			e = sys.exc_info()
			print(str(e[0]) + '\r\n' + str(e[1]))

		return True
