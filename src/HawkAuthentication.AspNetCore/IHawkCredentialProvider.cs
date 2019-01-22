using System.Threading.Tasks;

namespace HawkAuthentication.AspNetCore
{
    public interface IHawkCredentialProvider
    {
        Task<HawkCredential> GetKeyByKeyIdAsync(string keyId);
    }
}
