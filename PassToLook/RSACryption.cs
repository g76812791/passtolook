using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace PassToLook
{
    public class RSACryption
    {
        private static string publicKey =
            "<RSAKeyValue><Modulus>6CdsXgYOyya/yQH" +
            "TO96dB3gEurM2UQDDVGrZoe6RcAVTxAqDDf5L" +
            "wPycZwtNOx3Cfy44/D5Mj86koPew5soFIz9sx" +
            "PAHRF5hcqJoG+q+UfUYTHYCsMH2cnqGVtnQiE" +
            "/PMRMmY0RwEfMIo+TDpq3QyO03MaEsDGf13sP" +
            "w9YRXiac=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        private static string privateKey =
            "<RSAKeyValue><Modulus>6CdsXgYOyya/yQH" +
            "TO96dB3gEurM2UQDDVGrZoe6RcAVTxAqDDf5L" +
            "wPycZwtNOx3Cfy44/D5Mj86koPew5soFIz9sx" +
            "PAHRF5hcqJoG+q+UfUYTHYCsMH2cnqGVtnQiE" +
            "/PMRMmY0RwEfMIo+TDpq3QyO03MaEsDGf13sP" +
            "w9YRXiac=</Modulus><Exponent>AQAB</Exponent>" +
            "<P>/aoce2r6tonjzt1IQI6FM4ysR40j/gKvt4d" +
            "L411pUop1Zg61KvCm990M4uN6K8R/DUvAQdrRd" +
            "VgzvvAxXD7ESw==</P><Q>6kqclrEunX/fmOle" +
            "VTxG4oEpXY4IJumXkLpylNR3vhlXf6ZF9obEpG" +
            "lq0N7sX2HBxa7T2a0WznOAb0si8FuelQ==</Q>" +
            "<DP>3XEvxB40GD5v/Rr4BENmzQW1MBFqpki6FU" +
            "GrYiUd2My+iAW26nGDkUYMBdYHxUWYlIbYo6Te" +
            "zc3d/oW40YqJ2Q==</DP><DQ>LK0XmQCmY/ArY" +
            "gw2Kci5t51rluRrl4f5l+aFzO2K+9v3PGcndjA" +
            "StUtIzBWGO1X3zktdKGgCLlIGDrLkMbM21Q==</DQ><InverseQ>" +
            "GqC4Wwsk2fdvJ9dmgYlej8mTDBWg0Wm6aqb5kjn" +
            "cWK6WUa6CfD+XxfewIIq26+4Etm2A8IAtRdwPl4" +
            "aPjSfWdA==</InverseQ><D>a1qfsDMY8DSxB2D" +
            "Cr7LX5rZHaZaqDXdO3GC01z8dHjI4dDVwOS5ZFZ" +
            "s7MCN3yViPsoRLccnVWcLzOkSQF4lgKfTq3IH40" +
            "H5N4gg41as9GbD0g9FC3n5IT4VlVxn9ZdW+WQry" +
            "oHdbiIAiNpFKxL/DIEERur4sE1Jt9VdZsH24CJE=</D></RSAKeyValue>";
        /// <summary>
        /// RSA的加密函数  string
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="plaintext">明文</param>
        /// <returns></returns>
        public static string Encrypt(string plaintext)
        {
            return Encrypt(Encoding.UTF8.GetBytes(plaintext));
        }

        /// <summary>
        /// RSA的加密函数  string
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="plainbytes">明文字节数组</param>
        /// <returns></returns>
        public static string Encrypt(byte[] plainbytes)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey);
                var bufferSize = (rsa.KeySize / 8 - 11);
                byte[] buffer = new byte[bufferSize];//待加密块

                using (MemoryStream msInput = new MemoryStream(plainbytes))
                {
                    using (MemoryStream msOutput = new MemoryStream())
                    {
                        int readLen;
                        while ((readLen = msInput.Read(buffer, 0, bufferSize)) > 0)
                        {
                            byte[] dataToEnc = new byte[readLen];
                            Array.Copy(buffer, 0, dataToEnc, 0, readLen);
                            byte[] encData = rsa.Encrypt(dataToEnc, false);
                            msOutput.Write(encData, 0, encData.Length);
                        }

                        byte[] result = msOutput.ToArray();
                        rsa.Clear();
                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        /// <summary>
        /// RSA的解密函数  stirng
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="ciphertext">密文字符串</param>
        /// <returns></returns>
        public static string Decrypt( string ciphertext)
        {
            return Decrypt( Convert.FromBase64String(ciphertext));
        }

        /// <summary>
        /// RSA的解密函数  byte
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherbytes">密文字节数组</param>
        /// <returns></returns>
        public static string Decrypt( byte[] cipherbytes)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey);
                int keySize = rsa.KeySize / 8;
                byte[] buffer = new byte[keySize];
                using (MemoryStream msInput = new MemoryStream(cipherbytes))
                {
                    using (MemoryStream msOutput = new MemoryStream())
                    {
                        int readLen;

                        while ((readLen = msInput.Read(buffer, 0, keySize)) > 0)
                        {
                            byte[] dataToDec = new byte[readLen];
                            Array.Copy(buffer, 0, dataToDec, 0, readLen);
                            byte[] decData = rsa.Decrypt(dataToDec, false);
                            msOutput.Write(decData, 0, decData.Length);
                        }

                        byte[] result = msOutput.ToArray();
                        rsa.Clear();

                        return Encoding.UTF8.GetString(result);
                    }
                }
            }
        }
    }
}