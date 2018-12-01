using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace RsaKeyGen
{

    /// <summary>
    /// RSA密钥格式转换,主要代码来源：https://blog.csdn.net/starfd/article/details/51838589
    /// </summary>
    public static class RSAConverter
    {
        /// <summary>    
        /// RSA私钥格式转换，java->.net    
        /// </summary>    
        /// <param name="privateKey">java生成的RSA私钥</param>    
        /// <returns></returns>   
        public static RSAParameters PrivateKey_Java2DotNet(this string privateKey)
        {
            var kp = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            var result = new RSAParameters
            {
                Modulus = kp.Modulus.ToByteArrayUnsigned(),
                Exponent = kp.PublicExponent.ToByteArrayUnsigned(),
                D = kp.Exponent.ToByteArrayUnsigned(),
                P = kp.P.ToByteArrayUnsigned(),
                Q = kp.Q.ToByteArrayUnsigned(),
                DP = kp.DP.ToByteArrayUnsigned(),
                DQ = kp.DQ.ToByteArrayUnsigned(),
                InverseQ = kp.QInv.ToByteArrayUnsigned(),
            };
            return result;
        }


        /// <summary>    
        /// RSA私钥格式转换，.net->java    
        /// </summary>    
        /// <param name="param">.net生成的私钥</param>    
        /// <returns></returns>   
        public static string PrivateKey_DotNet2Java(this RSAParameters param)
        {
            var privateKeyParam = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, param.Modulus),
                new BigInteger(1, param.Exponent),
                new BigInteger(1, param.D),
                new BigInteger(1, param.P),
                new BigInteger(1, param.Q),
                new BigInteger(1, param.DP),
                new BigInteger(1, param.DQ),
                new BigInteger(1, param.InverseQ)
                );
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
            var serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
            var result = Convert.ToBase64String(serializedPrivateBytes);
            return result;
        }
        /// <summary>    
        /// RSA公钥格式转换，java->.net    
        /// </summary>    
        /// <param name="publicKey">java生成的公钥</param>    
        /// <returns></returns>    
        public static RSAParameters PublicKey_Java2DotNet(this string publicKey)
        {
            var kp = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            var result = new RSAParameters
            {
                Modulus = kp.Modulus.ToByteArrayUnsigned(),
                Exponent = kp.Exponent.ToByteArrayUnsigned(),
            };
            return result;
        }
        /// <summary>    
        /// RSA公钥格式转换，.net->java    
        /// </summary>    
        /// <param name="publicKey">.net生成的公钥</param>    
        /// <returns></returns>   
        public static string PublicKey_DotNet2Java(this RSAParameters param)
        {
            var pub = new RsaKeyParameters(
                false,
                new BigInteger(1, param.Modulus),
                new BigInteger(1, param.Exponent)
                );
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
            var serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            var result = Convert.ToBase64String(serializedPublicBytes);
            return result;

        }





    }
}