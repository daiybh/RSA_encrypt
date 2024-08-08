using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;

namespace RSADemoOnNetCore
{
    class Program
    {
        static void Main(string[] args)
        {
            String context = "api123456";
            String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4L06Q/DeQAxK3jSRKIE766QhWwqctYbheyzOW9gKT76urVrdOoN0EM/GlIAIVu93jtN7li1YPS21Vic7UF5eDcQm7hsFGIZZ4WHjZy7dFJkzGeKY+sSHiLTTCMkfhYMkFhsTxo7zIkDwqL9nGbrrkacuqDydM/AA+7gZnVm+Q2wIDAQAB";
            publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgsyBqzXd+tjPUWLeXj8Kbt5zEmUWlQSUpxhgFafDq3jz637tB6GkoQ+EIDf05WUFRgqV2b97kyekJM38Hrd5uttafRlCHZgvz+chnGPQ/MLAq4mMtPMh7Doo/ECMcvyouPX1Q9S/tTfGQGqDRtG0ndTE0nqsxn31eb/FE161cBQIDAQAB";
            
            Console.WriteLine(encryptByPublicKey(context,publicKey));
            
        }
        private static String encryptByPublicKey(String context, String publicKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            ///rsa.FromXmlString(ConvertToXmlPublicJavaKey(publicKey));
            rsa.ImportParameters(FromXmlStringExtensions(ConvertToXmlPublicJavaKey(publicKey)));
            byte[] byteText = System.Text.Encoding.UTF8.GetBytes(context);
            byte[] byteEntry = rsa.Encrypt(byteText,false);
            return Convert.ToBase64String(byteEntry);
        }

        public static RSAParameters FromXmlStringExtensions(string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            System.Xml.XmlDocument xmlDoc = new System.Xml.XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (System.Xml.XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            return parameters;
        }

        public static string ConvertToXmlPublicJavaKey(string publicJavaKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicJavaKey));
            string xmlpublicKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
              Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
              Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
            Console.WriteLine(xmlpublicKey);
            Console.WriteLine("\n\n\n\n");
            return xmlpublicKey;
        }
    }
}
