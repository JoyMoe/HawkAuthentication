using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using HawkAuthentication;
using HawkAuthentication.AspNetCore;

namespace WebApi
{
    public class VirtualHawkCredentialProvider : IHawkCredentialProvider
    {
        private readonly IEnumerable<HawkCredential> _credentials = new List<HawkCredential>
        {
            new HawkCredential {KeyId = "dh37fgj492je", Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"}
        };

        public Task<HawkCredential> GetKeyByKeyIdAsync(string keyId)
        {
            return Task.FromResult(_credentials.FirstOrDefault(c => c.KeyId == keyId));
        }
    }
}