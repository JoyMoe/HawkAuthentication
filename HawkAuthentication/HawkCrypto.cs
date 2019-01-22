using System;
using System.Security.Cryptography;
using System.Text;

namespace HawkAuthentication
{
    public static class HawkCrypto
    {
        public static string RandomString(int bytes = 20)
        {
            using (var provider = new RNGCryptoServiceProvider()) {
                var byteArray = new byte[bytes];
                provider.GetBytes(byteArray);
                return Convert.ToBase64String(byteArray);
            }
        }
        
        public static string CalculateHmac(string key, string plaintext)
        {
            using (var hash = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                return Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(plaintext)));
            }
        }

        public static string CalculatePayloadHash(string contentType, string payload)
        {
            var normalizedPayload = $"{HawkConstants.HeaderPrefix}.{HawkConstants.Version}.payload\n" +
                                    $"{contentType}\n" +
                                    $"{payload}\n";

            using (var hash = SHA256.Create())
            {
                return Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(normalizedPayload)));
            }
        }

        public static string CalculateMac(string key, long ts, string nonce, string method, string query, string hostname, int port, string hash = null, string ext = null)
        {
            var normalizedRequest = $"{HawkConstants.HeaderPrefix}.{HawkConstants.Version}.header\n" +
                                    $"{ts}\n" +
                                    $"{nonce}\n" +
                                    $"{method.ToUpper()}\n" +
                                    $"{query}\n" +
                                    $"{hostname}\n" +
                                    $"{port}\n" +
                                    $"{hash}\n" +
                                    $"{ext}\n";

            return CalculateHmac(key, normalizedRequest);
        }

        public static string CalculateTsMac(string key, long timestamp)
        {
            return CalculateHmac(key, $"{HawkConstants.HeaderPrefix}.{HawkConstants.Version}.ts\n{timestamp}\n");
        }
    }
}