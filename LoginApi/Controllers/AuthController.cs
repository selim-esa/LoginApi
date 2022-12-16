using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Security.Cryptography;

namespace LoginApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {


        public static User user = new User();
        private readonly IConfiguration configuration;

        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost("register")]

        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.Name = request.Name;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            return Ok(user);
        }

        [HttpPost("login")]

        public async Task<ActionResult<string>> Login(UserDto request)
        {

            if (user.Name != request.Name)
            {
                return BadRequest("yanlışş");
               
            }

            if (!VerifyPasswordHash(request.Password,user.PasswordHash,user.PasswordSalt))
            {
                return BadRequest("wrong password");
            }

            string token = CreateToken(user);
           
             return Ok(token);
            
           }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.Name)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(

                configuration.GetSection("AppSettings.Token").Value ));

               
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
            


      private void CreatePasswordHash(string password , out byte[] passwordHash, out byte[] passwordSalt )
        { 
            using(var hmac =new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash= hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }


        }

        private bool VerifyPasswordHash(string password, byte[] passwordSalt, byte[] passwordHash)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var ComputedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return ComputedHash.SequenceEqual(passwordHash);

            }
        }
    }
}
