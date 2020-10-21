namespace JoyMoe.HawkAuthentication
{
    public class HawkCredential
    {
        public string KeyId { get; set; } = null!;

        public string Key { get; set; } = null!;

        public bool RequirePayloadHash { get; set; }
    }
}
