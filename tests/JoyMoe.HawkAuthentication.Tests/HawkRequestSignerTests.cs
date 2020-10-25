using System;
using System.Net.Http;
using System.Threading.Tasks;
using JoyMoe.HawkAuthentication.Client;
using Xunit;

namespace JoyMoe.HawkAuthentication.Tests
{
    public class HawkRequestSignerTests
    {
        private readonly HawkRequestSigner _signer;

        public HawkRequestSignerTests()
        {
            _signer = new HawkRequestSigner(new HawkCredential
            {
                KeyId = "dh37fgj492je",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
            });
        }

        [Fact]
        public async Task SigningTests()
        {
            using var request = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri("http://example.com:8000/resource/1?b=1&a=2")
            };

            await _signer.SignAsync(request).ConfigureAwait(false);

            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal(HawkConstants.AuthenticationScheme, request.Headers.Authorization!.Scheme);
        }

        [Fact]
        public async Task SigningWithPayloadTests()
        {
            using var request = new HttpRequestMessage
            {
                Content = new StringContent("Thank you for flying Hawk"),
                Method = HttpMethod.Post,
                RequestUri = new Uri("http://example.com:8000/resource/1?b=1&a=2")
            };

            await _signer.SignAsync(request, "text/plain", requirePayloadHash: true).ConfigureAwait(false);

            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal(HawkConstants.AuthenticationScheme, request.Headers.Authorization!.Scheme);
        }
    }
}
