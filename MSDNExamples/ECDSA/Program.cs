using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

// https://msdn.microsoft.com/en-us/library/system.security.cryptography.ecdsacng(v=vs.140).aspx
namespace ECDSA
{
    class Alice
    {
        public static void Main(string[] args)
        {
            Bob bob = new Bob();
            using (ECDsaCng dsa = new ECDsaCng())
            {
                dsa.HashAlgorithm = CngAlgorithm.Sha256;
                bob.key = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);

                byte[] data = new byte[] { 21, 5, 8, 12, 207 };

                byte[] signature = dsa.SignData(data);

                bob.Receive(data, signature);
            }
        }


    }
    public class Bob
    {
        public byte[] key;

        public void Receive(byte[] data, byte[] signature)
        {
            using (ECDsaCng ecsdKey = new ECDsaCng(CngKey.Import(key, CngKeyBlobFormat.EccPublicBlob)))
            {
                if (ecsdKey.VerifyData(data, signature))
                    Console.WriteLine("Data is good");
                else
                    Console.WriteLine("Data is bad");
            }
        }
    }
}
