using System.Linq;
using System.Security.Claims;
using HawkAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers
{
    [Authorize(AuthenticationSchemes = HawkConstants.AuthenticationScheme)]
    public class ApiController : ControllerBase
    {
        // GET api/client
        [HttpGet("~/api/client")]
        public ActionResult<string> Client()
        {
            return User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
        }
    }
}
