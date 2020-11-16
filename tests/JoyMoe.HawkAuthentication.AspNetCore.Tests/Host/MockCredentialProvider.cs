using System.Threading.Tasks;

namespace JoyMoe.HawkAuthentication.AspNetCore.Tests.Host
{
    public class MockCredentialProvider : IHawkCredentialProvider
    {
        public static readonly HawkCredential Credential = new()
        {
            KeyId = "dh37fgj492je",
            Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
        };

        public Task<HawkCredential?> GetKeyByKeyIdAsync(string keyId)
        {
            var credential = Credential.KeyId == keyId ? Credential : null;

            return Task.FromResult(credential);
        }
    }
}
