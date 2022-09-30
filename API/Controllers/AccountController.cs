using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }
        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO register)
        {
            if (await UserExists(register.userName)) return BadRequest("user name is taken!");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                Username = register.userName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(register.password)),
                PasswordSalt = hmac.Key,
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDTO
            {
                userName = user.Username,
                token = _tokenService.CreatToken(user),
            };
        }
        private async Task<bool> UserExists(string userName)
        {
            return await _context.Users.AnyAsync(x => x.Username == userName.ToLower());
        }
        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> login(LoginDTO loginDTO)
        {
            var user = await _context.Users
                .SingleOrDefaultAsync(x => x.Username == loginDTO.userName);
           
            if (user == null) return Unauthorized("Invalid user name");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash =hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }
            return new UserDTO
            {
                userName = user.Username,
                token = _tokenService.CreatToken(user),
            };
        }
    }
}
