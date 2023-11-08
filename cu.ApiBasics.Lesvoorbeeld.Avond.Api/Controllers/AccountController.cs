using cu.ApiBasics.Lesvoorbeeld.Avond.Api.DTOs.Account;
using cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace cu.ApiBasics.Lesvoorbeeld.Avond.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;


        public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginRequestDto loginRequestDto)
        {
            //check credentials
            var result = await _signInManager.PasswordSignInAsync(loginRequestDto.Username,loginRequestDto.Password
                ,false,false);
            if(!result.Succeeded)
            {
                return Unauthorized();
            }
            //get the user
            var user = await _userManager.FindByNameAsync(loginRequestDto.Username);
            //get the user roles
            var userRoles = await _userManager.GetRolesAsync(user);
            //get the claims
            var claims = await _userManager.GetClaimsAsync(user);
            //add userId to claims
            claims.Add(new Claim(ClaimTypes.PrimarySid, user.Id));
            //add user roles to claims
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            //generate token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("JWTConfiguration:SigninKey")));

            var token = new JwtSecurityToken(
                    audience: _configuration.GetValue<string>("JWTConfiguration:Audience"),
                    issuer: _configuration.GetValue<string>("JWTConfiguration:Issuer"),
                    claims: claims,
                    expires: DateTime.Now.AddDays(_configuration.GetValue<int>("JWTConfiguration:TokenExpiration")),
                    signingCredentials: new SigningCredentials(key,SecurityAlgorithms.HmacSha256)
                );
            //serialize token
            var serializedToken = new JwtSecurityTokenHandler().WriteToken(token);
            return Ok(serializedToken);
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterRequestDto registerRequestDto)
        {
            //check modelstate
            //create a new user
            var applicationUser = new ApplicationUser 
            {
                UserName = registerRequestDto.Username,
                Email = registerRequestDto.Username,
                Firstname = registerRequestDto.Firstname,
                Lastname = registerRequestDto.Lastname,
            }; 
            //add user role to user
            var result = await _userManager.CreateAsync(applicationUser,registerRequestDto.Password);
            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            //use _signinmanager to add new user
            result = await _userManager.AddToRoleAsync(applicationUser, "User");
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            return Ok("User created");
        }
    }
}
