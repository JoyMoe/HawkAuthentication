using System.Threading.Tasks;

namespace HawkAuthentication.AspNetCore
{
    public interface IHawkAuthenticationKeyProvider
    {
        Task<HawkCredential> GetKeyByKeyIdAsync(string keyId);
    }
}