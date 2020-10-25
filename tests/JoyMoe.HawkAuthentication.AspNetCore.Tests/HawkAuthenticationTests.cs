using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using JoyMoe.HawkAuthentication.AspNetCore.Tests.Host;
using JoyMoe.HawkAuthentication.Client;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace JoyMoe.HawkAuthentication.AspNetCore.Tests
{
    public class HawkAuthenticationTests
    {
        [Fact]
        public async Task UnsignedRequestShouldGetUnauthorized()
        {
            using var host = await TestHostBuilder.BuildAsync().ConfigureAwait(false);

            var client = host.GetTestClient();

            var response = await client.GetAsync(new Uri("https://example.com/Test/Authorized")).ConfigureAwait(false);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains(HawkConstants.AuthenticationScheme, response.Headers.WwwAuthenticate.ToString(), StringComparison.InvariantCultureIgnoreCase);
        }

        [Fact]
        public async Task SignedGetRequestShouldGetOkResponse()
        {
            var signer = new HawkRequestSigner(MockCredentialProvider.Credential);

            using var host = await TestHostBuilder.BuildAsync().ConfigureAwait(false);

            var client = host.GetTestClient();

            using var message = new HttpRequestMessage
            {
                RequestUri = new Uri("https://example.com/Test/Authorized"),
                Method = HttpMethod.Get
            };

            await signer.SignAsync(message).ConfigureAwait(false);

            var response = await client.SendAsync(message).ConfigureAwait(false);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Equal("Hello World!", await response.Content.ReadAsStringAsync().ConfigureAwait(false));
        }

        [Fact]
        public async Task SignedPostRequestShouldGetOkResponse()
        {
            var signer = new HawkRequestSigner(MockCredentialProvider.Credential);

            using var host = await TestHostBuilder.BuildAsync().ConfigureAwait(false);

            var client = host.GetTestClient();

            using var message = new HttpRequestMessage
            {
                RequestUri = new Uri("https://example.com/Test/Authorized"),
                Method = HttpMethod.Post,
                Content = new StringContent("Hello")
            };

            await signer.SignAsync(message).ConfigureAwait(false);

            var response = await client.SendAsync(message).ConfigureAwait(false);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Equal("Hello World!", await response.Content.ReadAsStringAsync().ConfigureAwait(false));
        }
    }
}
