using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace JoyMoe.HawkAuthentication.Client
{
    public class HawkRequestSigner
    {
        private readonly HawkCredential _credential;

        public HawkRequestSigner(HawkCredential credential)
        {
            _credential = credential;
        }

        public async Task SignAsync(HttpRequestMessage request, string? ext = null, bool requirePayloadHash = false)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            request.Headers.Host ??= request.RequestUri?.Host;

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var nonce = HawkCrypto.RandomString();
            var hash = "";

            if (requirePayloadHash || _credential.RequirePayloadHash)
            {
                if (request.Content == null)
                {
                    throw new ArgumentNullException(nameof(request));
                }

                var contentType = request.Content.Headers.ContentType?.MediaType;
                if (string.IsNullOrWhiteSpace(contentType))
                {
                    throw new NullReferenceException(nameof(contentType));
                }

                hash = HawkCrypto.CalculatePayloadHash(contentType, await request.Content.ReadAsStringAsync().ConfigureAwait(false));
            }

            if (request.RequestUri == null)
            {
                throw new NullReferenceException();
            }

            var mac = HawkCrypto.CalculateMac(_credential.Key, timestamp, nonce, request.Method.Method, request.RequestUri.PathAndQuery, request.RequestUri.Host, request.RequestUri.Port, hash, ext);

            var signature = new HawkSignature
            {
                KeyId = _credential.KeyId,
                Timestamp = timestamp,
                Nonce = nonce,
                Hash = hash,
                Ext = ext,
                Mac = mac
            };

            var header = $"{HawkConstants.AuthenticationScheme} {signature}";

            request.Headers.TryAddWithoutValidation("Authorization", header);
        }
    }
}
