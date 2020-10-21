using System.Threading.Tasks;

namespace JoyMoe.HawkAuthentication.AspNetCore
{
    public interface IHawkCredentialProvider
    {
        Task<HawkCredential?> GetKeyByKeyIdAsync(string keyId);
    }
}
