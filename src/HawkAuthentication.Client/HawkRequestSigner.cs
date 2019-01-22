using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace HawkAuthentication.Client
{
    public class HawkRequestSigner
    {
        private readonly HawkCredential _credential;

        public HawkRequestSigner(HawkCredential credential)
        {
            _credential = credential;
        }

        public async Task<HttpRequestMessage> SignAsync(HttpRequestMessage request, string ext = null)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.Headers.Host == null)
            {
                request.Headers.Host = request.RequestUri.Host;
            }

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var nonce = HawkCrypto.RandomString();
            var hash = "";

            if (_credential.RequirePayloadHash)
            {
                hash = HawkCrypto.CalculatePayloadHash("", await request.Content.ReadAsStringAsync());
            }

            var mac = HawkCrypto.CalculateMac(_credential.Key, timestamp, nonce, request.Method.Method, request.RequestUri.PathAndQuery, request.RequestUri.Host, request.RequestUri.Port, hash, ext);

            var header = $"{HawkConstants.AuthenticationScheme} id=\"{_credential.KeyId}\", " +
                         $"ts=\"{timestamp}\", " +
                         $"nonce=\"{nonce}\", " +
                         (string.IsNullOrWhiteSpace(hash) ? "" : $"hash=\"{hash}\", ") +
                         (string.IsNullOrWhiteSpace(ext) ? "" : $"ext=\"{ext}\", ") +
                         $"mac=\"{mac}\"";

            request.Headers.TryAddWithoutValidation("Authorization", header);

            return request;
        }
    }
}
