using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MinimalAPI.Models;

namespace MinimalAPI.Controllers
{
    [Route("api/test")]
    [Authorize]
    [ApiController]
    public class welcomeConroller : ControllerBase
    {
        private readonly JwtTokenGenerator _jwtTokenGenerator;

        public welcomeConroller(JwtTokenGenerator jwtTokenGenerator)
        {
            _jwtTokenGenerator = jwtTokenGenerator;
        }

        [HttpGet("hello")]
        public IActionResult PrintHello()
        {
            if (User.Identity?.IsAuthenticated ?? false)
            {
                return Ok("Hello World!");
            }
            else
            {
                return Unauthorized("Not authenticated");
            }
        }


        [HttpPost("generate-token")]
        public IActionResult GenerateToken([FromBody] LoginRequest model)
        {
            var token = _jwtTokenGenerator.GenerateToken(model);

            if (token != null)
            {
                return Ok(new { Token = token });
            }
            else
            {
                return Unauthorized("Invalid credentials");
            }        
        }

    }
}