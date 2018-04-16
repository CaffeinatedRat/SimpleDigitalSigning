#LINUX BASH SCRIPT

#Replace PASSIN with your pfx password.
#NOTE: This a DEMO password only for the DemoCert.pfx file!
PASSIN="bd8d04b8aaa1f9c95c5629a1e995e2db"
PASSOUT="7fe29440cf8c64eff66bb50b9bd5612a"
PEMTEMP="temp.pem"
CERT="cert.pem"
PRIVATE_KEY="private.key"
PUBLIC_KEY="public.pem"

#Exports the private key as a pem cert.
openssl pkcs12 -in "$1" -out $PEMTEMP -nocerts -passin pass:$PASSIN -passout pass:$PASSOUT -nodes

#Extracts the private key from the pem cert.
openssl rsa -in $PEMTEMP -out $PRIVATE_KEY -passin pass:$PASSOUT

#Exports the public key as a cert.
openssl pkcs12 -in "$1" -clcerts -nokeys -out $CERT -passin pass:$PASSIN
rm -f $PEMTEMP

#Extracts the public key from the cert.
openssl x509 -pubkey -noout -in $CERT -passin pass:$PASSIN > $PUBLIC_KEY
rm -f $CERT
# 