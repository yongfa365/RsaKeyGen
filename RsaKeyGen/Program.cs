using System;
using System.IO;
using System.Security.Cryptography;

namespace RsaKeyGen
{
    class Program
    {
        static void Main(string[] args)
        {
            //可以自行修改这两个，但还是建议用这个工具直接生成Java及C#的
            var publicKey = string.Empty;
            var privateKey = string.Empty;

            if (publicKey == privateKey && publicKey == string.Empty)
            {
                //生成新的
                using (var provider = new RSACryptoServiceProvider())
                {
                    publicKey = SerializeHelper.ToXml(provider.ExportParameters(false));
                    privateKey = SerializeHelper.ToXml(provider.ExportParameters(true));
                }
            }

            var PublicKey = SerializeHelper.FromXml<RSAParameters>(publicKey);
            var PrivateKey = SerializeHelper.FromXml<RSAParameters>(privateKey);

            var basedir = $@"GenKeys\{DateTime.Now.ToString("yyyy-MM-dd HH-mm-ss-fff")}";
            var csharpPath = $@"{basedir}\C#\";
            var javaPath = $@"{basedir}\java\";
            var pythonPath = $@"{basedir}\Python\";
            var goPath = $@"{basedir}\go\";

            Directory.CreateDirectory(csharpPath);
            File.WriteAllText(csharpPath + "PublicKey.txt", publicKey);
            File.WriteAllText(csharpPath + "PrivateKey.txt", privateKey);



            Directory.CreateDirectory(javaPath);
            var javaPublicKey = RSAConverter.PublicKey_DotNet2Java(PublicKey);
            var javaPrivateKey = RSAConverter.PrivateKey_DotNet2Java(PrivateKey);
            File.WriteAllText(javaPath + "PublicKey.txt", javaPublicKey);
            File.WriteAllText(javaPath + "PrivateKey.txt", javaPrivateKey);

            //test code
            var xxx = RSAConverter.PublicKey_DotNet2Java(RSAConverter.PublicKey_Java2DotNet(javaPublicKey)) == javaPublicKey;
            var yyy = RSAConverter.PrivateKey_DotNet2Java(RSAConverter.PrivateKey_Java2DotNet(javaPrivateKey)) == javaPrivateKey;
            Console.WriteLine("Please See Current Dir");
            Console.ReadLine();
        }
    }
}
