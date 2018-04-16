using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace RegisterMessage.Helpers
{
    public class SimplerHasher
    {
        public enum HashType
        {
            MD5,
            RIPEMD160,
            SHA1,
            SHA256,
            SHA384,
            SHA512
        };

        /// <summary>
        /// Accepts a rawvalue and returns a message digest as an array of bytes based on the type <see cref="HashType"/>.
        /// </summary>
        /// <param name="rawValue">
        /// The value to be hashed.
        /// </param>
        /// <param name="hashType">
        /// The type of hashing.
        /// </param>
        /// <returns></returns>
        public static byte[] Hash(string rawValue, HashType hashType)
        {
            HashAlgorithm hashalgorithm = GetHashAlgorithm(hashType);
            return hashalgorithm.ComputeHash(Encoding.Default.GetBytes(rawValue));
        }

        /// <summary>
        /// Accepts a rawvalue and returns a base 64 message digest based on the type <see cref="HashType"/>.
        /// </summary>
        /// <param name="rawValue">
        /// The value to be hashed.
        /// </param>
        /// <param name="hashType">
        /// The type of hashing.
        /// </param>
        /// <returns></returns>
        public static string HashAsBase64String(string rawValue, HashType hashType)
        {
            return Convert.ToBase64String(Hash(rawValue, hashType));
        }

        /// <summary>
        /// Returns a hash algorithm based on the type specified in the parameter <see cref="HashType">hashType</see>
        /// </summary>
        /// <param name="hashType"></param>
        /// <returns>
        /// The specific hash algorithm.
        /// </returns>
        public static HashAlgorithm GetHashAlgorithm(HashType hashType)
        {
            switch (hashType)
            {
                case HashType.MD5:
                    return new MD5CryptoServiceProvider();

                case HashType.RIPEMD160:
                    return new RIPEMD160Managed();

                case HashType.SHA1:
                    return new SHA1Managed();

                case HashType.SHA256:
                    return new SHA256Managed();

                case HashType.SHA384:
                    return new SHA384Managed();

                case HashType.SHA512:
                    return new SHA512Managed();

                default:
                    return new MD5CryptoServiceProvider();
            }
        }
    }
}