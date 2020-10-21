using System;
using Microsoft.AspNetCore.Authentication;

namespace JoyMoe.HawkAuthentication.AspNetCore
{
    public static class HawkAuthenticationExtensions
    {
        public static AuthenticationBuilder AddHawk(this AuthenticationBuilder builder)
        {
            return builder.AddHawk(HawkConstants.AuthenticationScheme, options => { });
        }

        public static AuthenticationBuilder AddHawk(
            this AuthenticationBuilder builder,
            Action<HawkAuthenticationOptions> configuration)
        {
            return builder.AddHawk(HawkConstants.AuthenticationScheme, configuration);
        }

        public static AuthenticationBuilder AddHawk(
            this AuthenticationBuilder builder, string scheme,
            Action<HawkAuthenticationOptions> configuration)
        {
            if (builder == null)
            {
                throw new NullReferenceException(nameof(builder));
            }

            return builder.AddScheme<HawkAuthenticationOptions, HawkAuthenticationHandler>(scheme, configuration);
        }
    }
}
