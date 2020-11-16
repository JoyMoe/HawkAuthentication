using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JoyMoe.HawkAuthentication.AspNetCore
{
    public class HawkAuthenticationHandler : AuthenticationHandler<HawkAuthenticationOptions>
    {
        private readonly List<string> _additionalProperties = new();
        private readonly IHawkCredentialProvider _keyProvider;

        public HawkAuthenticationHandler(
            IOptionsMonitor<HawkAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IHawkCredentialProvider keyProvider) : base(options, logger, encoder, clock)
        {
            _keyProvider = keyProvider;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                //Authorization header not in request
                return AuthenticateResult.NoResult();
            }

            HawkSignature signature;

            try
            {
                signature = HawkSignature.Parse(Request.Headers["Authorization"]);
            }
            catch (ArgumentException e)
            {
                return AuthenticateResult.Fail(e.Message);
            }

            var credential = await _keyProvider.GetKeyByKeyIdAsync(signature.KeyId).ConfigureAwait(false);
            if (credential == null)
            {
                return AuthenticateResult.Fail("Invalid credentials");
            }

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (timestamp - signature.Timestamp > Options.TimestampSkewSec)
            {
                _additionalProperties.Add($"ts=\"{timestamp}\"");

                var tsm = HawkCrypto.CalculateTsMac(credential.Key, timestamp);
                _additionalProperties.Add($"tsm=\"{tsm}\"");

                return AuthenticateResult.Fail("Stale timestamp");
            }

            if (!string.IsNullOrWhiteSpace(signature.Hash))
            {
                using var stream = new StreamReader(Context.Request.Body);

                var payloadHash = HawkCrypto.CalculatePayloadHash(Context.Request.ContentType, await stream.ReadToEndAsync().ConfigureAwait(false));

                if (payloadHash != signature.Hash)
                {
                    return AuthenticateResult.Fail("Bad payload hash");
                }
            }
            else
            {
                if (credential.RequirePayloadHash)
                {
                    return AuthenticateResult.Fail("Missing required payload hash");
                }
            }

            var url = new Uri(Context.Request.GetDisplayUrl());
            var mac = HawkCrypto.CalculateMac(
                credential.Key,
                signature.Timestamp,
                signature.Nonce,
                Context.Request.Method,
                url.PathAndQuery,
                url.Host,
                url.Port,
                signature.Hash,
                signature.Ext
            );

            if (mac != signature.Mac)
            {
                return AuthenticateResult.Fail("Bad mac");
            }

            var claims = new[] {new Claim(ClaimTypes.NameIdentifier, credential.KeyId)};
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers["WWW-Authenticate"] = $"{HawkConstants.AuthenticationScheme} {string.Join(", ", _additionalProperties)}".Trim();

            await base.HandleChallengeAsync(properties).ConfigureAwait(false);
        }
    }
}
