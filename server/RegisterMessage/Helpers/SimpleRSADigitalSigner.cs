using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace RegisterMessage.Helpers
{
    public class SimpleRSADigitalSigner
    {
        public const string INVALID_PRIVATE_KEY_ERROR_MESSAGE = "The private RSA key is invalid.";
        public const string INVALID_PUBLIC_KEY_ERROR_MESSAGE = "The public RSA key is invalid.";

        #region Properties

        private X509Certificate2 Certificate { get; set; }
        public SimplerHasher.HashType HashAlgorithm { get; private set; }

        public bool fOAEP { get; set; }
        public RSACryptoServiceProvider PrivateKey { get; set; }
        public RSACryptoServiceProvider PublicKey { get; set; }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a SimpleRSADigitalSigner based on the hashing algorithm.  They PublicKey and PrivateKey properties must be set manually.
        /// </summary>
        /// <param name="hashAlgorithm">
        /// A supported requested hashing algorithm, defaulting to MD5 if none is passed.
        /// </param>
        public SimpleRSADigitalSigner(SimplerHasher.HashType hashAlgorithm = SimplerHasher.HashType.MD5, bool fOAEP = true)
        {
            this.HashAlgorithm = hashAlgorithm;
            this.fOAEP = fOAEP;
        }

        /// <summary>
        /// Creates a SimpleRSADigitalSigner based on the path of the X509 Cert, password, and hashing algorithm.
        /// </summary>
        /// <param name="path">
        /// The file path of the cert.
        /// </param>
        /// <param name="password">
        /// The password required to open the X509 Cert.
        /// </param>
        /// <param name="hashAlgorithm">
        /// A supported requested hashing algorithm, defaulting to MD5 if none is passed.
        /// </param>
        public SimpleRSADigitalSigner(string path, string password, SimplerHasher.HashType hashAlgorithm = SimplerHasher.HashType.MD5)
            : this(hashAlgorithm)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException("path");
            }

            this.Certificate = new X509Certificate2(path, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            //Retrieve the public and private RSA keys early.
            //Even though this is stored in the cert, let's kept the logic simple and assign these properites when we have either key.
            this.PrivateKey = Certificate.PrivateKey as RSACryptoServiceProvider;
            this.PublicKey = Certificate.PublicKey.Key as RSACryptoServiceProvider;

            if (this.PrivateKey == null)
            {
                throw new InvalidCastException("The certificate's private key is not RSA based.");
            }

            if (this.PublicKey == null)
            {
                throw new InvalidCastException("The certificate's public key is not RSA based.");
            }
        }

        /// <summary>
        /// Imports private and public RSA keys as a set of byte arrays.
        /// </summary>
        /// <param name="privateKey">
        /// A valid private RSA key.
        /// </param>
        /// <param name="publicKey">
        /// A valid public RSA Key.
        /// </param>
        public void Import(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException("privateKey");
            }

            if (publicKey == null)
            {
                throw new ArgumentNullException("publicKey");
            }

            this.PrivateKey = new RSACryptoServiceProvider();
            this.PrivateKey.ImportCspBlob(privateKey);

            this.PublicKey = new RSACryptoServiceProvider();
            this.PublicKey.ImportCspBlob(publicKey);
        }

        /// <summary>
        /// Imports private and public RSA keys in a base 64 encoding form.
        /// </summary>
        /// <param name="privateKey">
        /// A valid private RSA key.
        /// </param>
        /// <param name="publicKey">
        /// A valid public RSA Key.
        /// </param>
        public void Import(string privateKey, string publicKey)
        {
            if (string.IsNullOrEmpty(privateKey))
            {
                throw new ArgumentNullException("privateKey");
            }

            if (string.IsNullOrEmpty(publicKey))
            {
                throw new ArgumentNullException("publicKey");
            }

            Import(Convert.FromBase64String(privateKey), Convert.FromBase64String(publicKey));
        }

        /// <summary>
        /// Export the private RSA key blob.
        /// </summary>
        /// <returns></returns>
        public byte[] ExportPrivateKeyBlob()
        {
            if (this.PrivateKey == null)
            {
                throw new NullReferenceException(INVALID_PRIVATE_KEY_ERROR_MESSAGE);
            }

            return this.PrivateKey.ExportCspBlob(true);
        }

        /// <summary>
        /// Export the public RSA key blob.
        /// </summary>
        /// <returns></returns>
        public byte[] ExportPublicKeyBlob()
        {
            if (this.PublicKey == null)
            {
                throw new NullReferenceException(INVALID_PUBLIC_KEY_ERROR_MESSAGE);
            }

            return this.PublicKey.ExportCspBlob(false);
        }

        /// <summary>
        /// Signs the plaintext message and returns the signature as an array of bytes.
        /// </summary>
        /// <param name="plainTextMessage">
        /// Plaintext message to sign.
        /// </param>
        /// <returns></returns>
        public byte[] SignMessage(string plainTextMessage)
        {
            if (this.PrivateKey == null)
            {
                throw new NullReferenceException(INVALID_PRIVATE_KEY_ERROR_MESSAGE);
            }

            RSAPKCS1SignatureFormatter RSAformatter = new RSAPKCS1SignatureFormatter(this.PrivateKey);
            RSAformatter.SetHashAlgorithm(this.HashAlgorithm.ToString());
            var hash = SimplerHasher.Hash(plainTextMessage, this.HashAlgorithm);
            return RSAformatter.CreateSignature(hash);
        }

        /// <summary>
        /// Signs the plaintext message and returns the signature as a base 64 encoded string.
        /// </summary>
        /// <param name="plainTextMessage">
        /// Plaintext message to sign.
        /// </param>
        /// <returns></returns>
        public string SignMessageAsBase64String(string plainTextMessage)
        {
            return Convert.ToBase64String(SignMessage(plainTextMessage));
        }

        /// <summary>
        /// Verify the plaintext message against the signature block.
        /// </summary>
        /// <param name="plainTextMessage"></param>
        /// <param name="signatureBlock">
        /// The signature block as an array of bytes.
        /// </param>
        /// <returns></returns>
        public bool VerifySignature(string plainTextMessage, byte[] signatureBlock)
        {
            //Throw an exception for invalid keys.
            if (this.PublicKey == null)
            {
                throw new NullReferenceException(INVALID_PUBLIC_KEY_ERROR_MESSAGE);
            }

            try
            {
                //Hash the plain text message.
                var hash = SimplerHasher.Hash(plainTextMessage, this.HashAlgorithm);

                //Compare it to the signature block.
                var deformatter = new RSAPKCS1SignatureDeformatter(this.PublicKey);
                deformatter.SetHashAlgorithm(HashAlgorithm.ToString());
                return deformatter.VerifySignature(hash, signatureBlock);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Verify the plaintext message against the signature block, where the signature is a base-64 encoded string.
        /// </summary>
        /// <param name="plainTextMessage"></param>
        /// <param name="signatureBlock">
        /// The signature block as a base-64 encoded string.
        /// </param>
        /// <returns></returns>
        public bool VerifySignature(string plainTextMessage, string signature)
        {
            return VerifySignature(plainTextMessage, Convert.FromBase64String(signature));
        }

        /// <summary>
        /// Encrypt the plaintext message.
        /// </summary>
        /// <param name="plainTextMessage">
        /// Plaintext message to be encrypted.
        /// </param>
        /// <returns>
        /// Returns the ciphertext as an array of bytes.
        /// </returns>
        public byte[] Encrypt(string plainTextMessage)
        {
            if (this.PublicKey == null)
            {
                throw new NullReferenceException("The public key is invalid.");
            }

            return this.PublicKey.Encrypt(Encoding.Default.GetBytes(plainTextMessage), this.fOAEP);
        }

        /// <summary>
        /// Encrypt the plaintext message as a base 64 encoded string.
        /// </summary>
        /// <param name="plainTextMessage">
        /// Plaintext message to be encrypted.
        /// </param>
        /// <returns>
        /// Returns the ciphertext as a base 64 encoded string
        /// </returns>
        public string EncryptAsBase64String(string plainTextMessage)
        {
            return Convert.ToBase64String(Encrypt(plainTextMessage));
        }

        /// <summary>
        /// Decrypts the ciphertext from an array of bytes.
        /// </summary>
        /// <param name="cipherText">
        /// The ciphertext as an array of bytes to be decrypted.
        /// </param>
        /// <returns>
        /// The plaintext message.
        /// </returns>
        public string Decrypt(byte[] cipherText)
        {
            if (this.PrivateKey == null)
            {
                throw new NullReferenceException("The private key is invalid.");
            }

            return Encoding.Default.GetString(this.PrivateKey.Decrypt(cipherText, this.fOAEP));
        }

        /// <summary>
        /// Decrypts the ciphertext from a base 64 encoded string.
        /// </summary>
        /// <param name="base64EncryptedMessage">
        /// The ciphertext as a base 64 encoded string to be decrypted.
        /// </param>
        /// <returns>
        /// The plaintext message.
        /// </returns>
        public string Decrypt(string cipherText)
        {
            return Decrypt(Convert.FromBase64String(cipherText));
        }

        #endregion Methods
    }
}