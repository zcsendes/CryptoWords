
namespace CryptoWords
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    class Program
    {
        private static readonly string SaltString = "5795500A-DEDC-4782-9DD4-498AC0D01D79";

        static void Main(string[] args)
        {
            try
            {
                Console.Write("(E)ncrypt or (D)ecrypt: ");
                var mode = Console.ReadLine();
                if (string.IsNullOrEmpty(mode))
                {
                    throw new Exception("Invalid mode");
                }

                string password;
                string text;
                string hexString;

                switch (mode.ToUpper())
                {
                    case "E":
                        const int maxWords = 24;

                        Console.Write($"Word count (1-{maxWords}): ");
                        var wordCount = int.Parse(Console.ReadLine());
                        if (wordCount < 1 || wordCount > maxWords)
                        {
                            throw new Exception("Invalid word count");
                        }

                        Console.Write("Password: ");
                        password = Console.ReadLine();
                        if (string.IsNullOrEmpty(password))
                        {
                            throw new Exception("Invalid password");
                        }

                        Console.Write("Re-type password: ");
                        var passwordReType = Console.ReadLine();
                        if (string.IsNullOrEmpty(passwordReType))
                        {
                            throw new Exception("Invalid password");
                        }

                        if (password != passwordReType)
                        {
                            throw new Exception("Invalid password");
                        }

                        var wordList = new List<string>();

                        for (int n = 0; n < wordCount; n++)
                        {
                            Console.Write($"Word #{n + 1}: ");
                            var word = Console.ReadLine();
                            if (string.IsNullOrEmpty(word))
                            {
                                throw new Exception("Invalid word");
                            }

                            wordList.Add(word);
                        }

                        Console.WriteLine();

                        text = string.Join(' ', wordList);
                        Console.WriteLine(text);

                        var cipherText = EncryptString(text, password);

                        var text2 = DecryptString(cipherText, password);
                        if (text2 != text)
                        {
                            throw new Exception("Unexpected error");
                        }

                        var buf = Convert.FromBase64String(cipherText);
                        hexString = BitConverter.ToString(buf).Replace("-", " ");

                        var cipherText2 = Convert.ToBase64String(ConvertFrom(hexString.Replace(" ", string.Empty)));
                        if (cipherText2 != cipherText)
                        {
                            throw new Exception("Unexpected error");
                        }

                        Console.WriteLine();
                        Console.WriteLine(cipherText);
                        Console.WriteLine(hexString);
                        break;

                    case "D":
                        Console.Write("Password: ");
                        password = Console.ReadLine();
                        if (string.IsNullOrEmpty(password))
                        {
                            throw new Exception("Invalid password");
                        }

                        Console.Write("Hex string (one line): ");
                        hexString = Console.ReadLine();
                        if (string.IsNullOrEmpty(password))
                        {
                            throw new Exception("Invalid hex string");
                        }

                        hexString = hexString.Replace("-", string.Empty);
                        hexString = hexString.Replace(" ", string.Empty);

                        cipherText = Convert.ToBase64String(ConvertFrom(hexString));

                        text = DecryptString(cipherText, password);
                        Console.WriteLine();
                        Console.WriteLine(text);
                        break;

                    default:
                        throw new Exception("Unsupported mode");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.ReadLine();
        }

        private static byte[] ConvertFrom(string hexString)
        {
            return Enumerable.Range(0, hexString.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                .ToArray();
        }

        private static string DecryptString(string cipherText, string password)
        {
            using (var aesAlg = NewRijndaelManaged(password, SaltString))
            {
                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                var cipher = Convert.FromBase64String(cipherText);

                using (var msDecrypt = new MemoryStream(cipher))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        private static string EncryptString(string text, string password)
        {
            using (var aesAlg = NewRijndaelManaged(password, SaltString))
            {
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }
                    }

                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        private static RijndaelManaged NewRijndaelManaged(string password, string salt)
        {
            if (string.IsNullOrEmpty(salt))
            {
                throw new ArgumentNullException(nameof(salt));
            }

            var saltBytes = Encoding.UTF8.GetBytes(salt);
            var key = new Rfc2898DeriveBytes(password, saltBytes);

            var aesAlg = new RijndaelManaged();
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
            aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

            return aesAlg;
        }
    }
}