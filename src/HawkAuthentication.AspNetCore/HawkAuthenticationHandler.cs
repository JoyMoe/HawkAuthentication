using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HawkAuthentication.AspNetCore
{
    public class HawkAuthenticationHandler : AuthenticationHandler<HawkAuthenticationOptions>
    {
        private readonly IHawkCredentialProvider _keyProvider;

        private readonly List<string> _additionalProperties = new List<string>();

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

            if(!AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"], out AuthenticationHeaderValue headerValue))
            {
                //Invalid Authorization header
                return AuthenticateResult.NoResult();
            }

            if(!"Hawk".Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                //Not Basic authentication header
                return AuthenticateResult.NoResult();
            }

            var regex = new Regex("(\\w+)=\"(.*)\"");
            var keyValuePairs = headerValue.Parameter.Split(',')
                .Select(p => regex.Match(p))
                .ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);

            if (!keyValuePairs.ContainsKey("id") ||
                !keyValuePairs.ContainsKey("ts") ||
                !keyValuePairs.ContainsKey("nonce") ||
                !keyValuePairs.ContainsKey("mac"))
            {
                return AuthenticateResult.Fail("Missing HAWK parameter");
            }

            var credential = await _keyProvider.GetKeyByKeyIdAsync(Context, keyValuePairs["id"]);
            if (credential == null)
            {
                return AuthenticateResult.Fail("Invalid credentials");
            }

            long.TryParse(keyValuePairs["ts"], out var ts);
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (timestamp - ts > Options.TimestampSkewSec) {
                _additionalProperties.Add($"ts=\"{timestamp}\"");

                var tsm = HawkCrypto.CalculateTsMac(credential.Key, timestamp);
                _additionalProperties.Add($"tsm=\"{tsm}\"");

                return AuthenticateResult.Fail("Stale timestamp");
            }

            keyValuePairs.TryGetValue("hash", out var hash);
            keyValuePairs.TryGetValue("ext", out var ext);

            if (!string.IsNullOrWhiteSpace(hash))
            {
                using (var stream = new StreamReader(Context.Request.Body))
                {
                    var payloadHash = HawkCrypto.CalculatePayloadHash(Context.Request.ContentType, stream.ReadToEnd());
                    if (payloadHash != hash)
                    {
                        return AuthenticateResult.Fail("Bad payload hash");
                    }
                }
            }
            else
            {
                if (credential.RequirePayloadHash)
                {
                    return AuthenticateResult.Fail("Missing required payload hash");
                }
            }

            var port = Request.Host.Port ?? Context.Connection.LocalPort;
            var mac = HawkCrypto.CalculateMac(credential.Key, long.Parse(keyValuePairs["ts"]), keyValuePairs["nonce"], Context.Request.Method, Context.Request.Path + Context.Request.QueryString, Context.Request.Host.Host, port, hash, ext);
            if (mac != keyValuePairs["mac"])
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

            await base.HandleChallengeAsync(properties);
        }
    }
}
