using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JoyMoe.HawkAuthentication.AspNetCore.Tests.Host
{
    [Route("Test")]
    public class TestApiController : ControllerBase
    {
        [Authorize]
        [HttpGet("Authorized")]
        public IActionResult AuthenticationGet()
        {
            return Ok("Hello World!");
        }

        [Authorize]
        [HttpPost("Authorized")]
        public IActionResult AuthenticationPost()
        {
            return Ok("Hello World!");
        }
    }
}
