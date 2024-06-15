using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers;
[Route("api/[controller]")]
[ApiController]
public class authController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;

    public authController(IConfiguration config, UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager)
    {
        _config = config;
        _userManager = userManager;
        _signInManager = signInManager;
    }
    [HttpPost("login")]
    public async Task<IActionResult> Login(AuthLoginRequestModel model)
    {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user != null)
        {
            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!result.Succeeded)
            {
                return Unauthorized("Wrong password");
            }
        }

        if (user == null)
        {
            return Unauthorized("Wrong username password");
        }
          
          
      
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescription = new SecurityTokenDescriptor
        {
            Issuer = _config["JWT:Issuer"],
            Audience = _config["JWT:Audience"],
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"])),
                SecurityAlgorithms.HmacSha256
            )
        };
        var token = tokenHandler.CreateToken(tokenDescription);
        return Ok(new
        {
            token = tokenHandler.WriteToken(token)
        });
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register(AuthLoginRequestModel model)
    {
        var user = new IdentityUser
        {
            UserName = model.UserName
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }
        return Ok();
    }
    [Authorize]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshRequestModel model)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(model.Token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _config["JWT:Issuer"],
            ValidAudience = _config["JWT:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]))
        }, out var validatedToken);
        var jwtToken = validatedToken as JwtSecurityToken;
        if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                StringComparison.InvariantCultureIgnoreCase))
        {
            return BadRequest("Invalid token");
        }
        var user = await _userManager.FindByIdAsync(principal.Identity?.Name);
        if (user == null)
        {
            return BadRequest("Invalid token");
        }
        var tokenDescription = new SecurityTokenDescriptor
        {
            Issuer = _config["JWT:Issuer"],
            Audience = _config["JWT:Audience"],
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"])),
                SecurityAlgorithms.HmacSha256
            )
        };
        var token = tokenHandler.CreateToken(tokenDescription);
        return Ok(new
        {
            token = tokenHandler.WriteToken(token)
        });
    }
    

    public class AuthLoginRequestModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
    public class RefreshRequestModel
    {
        [Required]
        public string Token { get; set; }
    }

   
    
    
    
}