using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace HawkAuthentication.AspNetCore
{
    public interface IHawkCredentialProvider
    {
        Task<HawkCredential> GetKeyByKeyIdAsync(HttpContext context, string keyId);
    }
}
