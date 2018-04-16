#Built on Python 2.7.6
#Version 1.0

#Internal modules
import sys
import threading
from datetime import datetime

#pycrypto (Version: 2.6.1)
#https://www.dlitz.net/software/pycrypto/
from Crypto.Hash import MD5

#SimpleRSADigitalSigner (Version: 1.0.0)
from SimpleRSADigitalSigning import SimpleRSADigitalSigner
from RegisterMessage import RegisterMessage

#Main execution.
threads = []
thread = RegisterMessage('Demo', 'http://<YourIPAddress>:64220/api/register/registerbaconmessage', lambda now:"How is the bacon?", 'certs/private.key', 'certs/public.pem', MD5.new())
thread.start()
threads.append(thread)

isAlive = True

#Control loop.
while isAlive:

	#Get the user input.
	input = raw_input('').lower()
	#Stop the control loop and shutdown the script.
	if input == 'stop':
		isAlive = False

#Clean-up
print('>>Stopping the script.\n')

for thread in threads:
	thread.stop()
