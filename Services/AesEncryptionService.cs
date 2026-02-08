using System.Security.Cryptography;
using System.Text;

namespace BookwormsOnline.Services
{
    public class AesEncryptionService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public AesEncryptionService(IConfiguration config)
        {
            var keyB64 = config["Crypto:Key"] ?? "";
            var ivB64 = config["Crypto:IV"] ?? "";

            if (string.IsNullOrWhiteSpace(keyB64) || string.IsNullOrWhiteSpace(ivB64))
                throw new InvalidOperationException("Crypto Key/IV not configured. Use User Secrets.");

            _key = Convert.FromBase64String(keyB64);
            _iv = Convert.FromBase64String(ivB64);

            if (_key.Length != 32) throw new InvalidOperationException("AES key must be 32 bytes (256-bit).");
            if (_iv.Length != 16) throw new InvalidOperationException("AES IV must be 16 bytes.");
        }

        public string EncryptToBase64(string plaintext)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            var bytes = Encoding.UTF8.GetBytes(plaintext);
            var cipher = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
            return Convert.ToBase64String(cipher);
        }

        public string DecryptFromBase64(string cipherBase64)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            var cipher = Convert.FromBase64String(cipherBase64);
            var plain = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
            return Encoding.UTF8.GetString(plain);
        }
    }
}
