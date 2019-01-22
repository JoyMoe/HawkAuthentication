using Microsoft.AspNetCore.Authentication;

namespace HawkAuthentication.AspNetCore
{
    public class HawkAuthenticationOptions : AuthenticationSchemeOptions
    {
        public int TimestampSkewSec { get; set; } = 60;
    }
}
