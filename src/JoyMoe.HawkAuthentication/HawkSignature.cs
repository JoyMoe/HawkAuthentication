using System;

namespace JoyMoe.HawkAuthentication
{
    public class HawkSignature
    {
        public string KeyId { get; set; } = null!;

        public long Timestamp { get; set; }

        public string Nonce { get; set; } = null!;

        public string Mac { get; set; } = null!;

        public string? Hash { get; set; }

        public string? Ext { get; set; }

        public static HawkSignature Parse(string authorization)
        {
            if (string.IsNullOrWhiteSpace(authorization))
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var separator = authorization.IndexOf(' ', StringComparison.InvariantCulture);

            if (separator < 0)
            {
                throw new ArgumentException("Invalid Authorization header");
            }

            var scheme = authorization.Substring(0, separator);
            if (!"Hawk".Equals(scheme, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Invalid Authorization scheme");
            }

            var parameters = authorization.Substring(separator + 1);

            if (string.IsNullOrWhiteSpace(parameters))
            {
                throw new ArgumentException("Missing HAWK parameter");
            }

            var signature = new HawkSignature();
            foreach (var part in parameters.Split(','))
            {
                var sign = part.IndexOf('=', StringComparison.InvariantCulture);

                var key = part.Substring(0, sign).Trim();
                var value = part.Substring(sign + 1).Trim('"');

                switch (key)
                {
                    case "id":
                        signature.KeyId = value;
                        break;
                    case "ts":
                        _ = long.TryParse(value, out var ts);
                        signature.Timestamp = ts;
                        break;
                    case "nonce":
                        signature.Nonce = value;
                        break;
                    case "mac":
                        signature.Mac = value;
                        break;
                    case "hash":
                        signature.Hash = value;
                        break;
                    case "ext":
                        signature.Ext = value;
                        break;
                    default:
                        continue;
                }
            }

            if (string.IsNullOrWhiteSpace(signature.KeyId) ||
                signature.Timestamp == default ||
                string.IsNullOrWhiteSpace(signature.Nonce) ||
                string.IsNullOrWhiteSpace(signature.Mac))
            {
                throw new ArgumentException("Missing HAWK parameter");
            }

            return signature;
        }

        public override string ToString()
        {
            return $"id=\"{KeyId}\", " +
                   $"ts=\"{Timestamp}\", " +
                   $"nonce=\"{Nonce}\", " +
                   (string.IsNullOrWhiteSpace(Hash) ? "" : $"hash=\"{Hash}\", ") +
                   (string.IsNullOrWhiteSpace(Ext) ? "" : $"ext=\"{Ext}\", ") +
                   $"mac=\"{Mac}\"";
        }
    }
}
