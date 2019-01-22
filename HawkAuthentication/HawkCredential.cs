namespace HawkAuthentication
{
    public class HawkCredential
    {
        public string KeyId { get; set; }

        public string Key { get; set; }

        public bool RequirePayloadHash { get; set; } = false;
    }
}