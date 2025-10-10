using UserService.Application.Interfaces;
using UserService.Application.Models;
using UserService.Domain.Entities;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration; // Cần config
namespace UserService.Application.Services
{
    public class TokenGenerator : ITokenGenerator
    {
        private readonly IConfiguration _config;
        public TokenGenerator(IConfiguration config)
        {
            _config = config;
        }

        public AuthResponse GenerateToken(User user, List<string> roleNames)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]); // Lấy key từ config

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                // new Claim(ClaimTypes.Role, user.UserRole)
            };

            foreach(var roleName in roleNames)
            {
                claims.Add(new Claim(ClaimTypes.Role, roleName)); // <-- Thêm nhiều lần
            }


            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(int.Parse(_config["Jwt:ExpirationHours"])),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var accessToken = tokenHandler.WriteToken(token);

            // Logic RefreshToken có thể phức tạp hơn, ở đây đơn giản hóa
            var refreshToken = Guid.NewGuid().ToString();

            return new AuthResponse
            {
                Id = user.Id.ToString(), // Chuyển Guid sang string
                Username = user.Username,
                Email = user.Email,
                // Role = roleNames.FirstOrDefault() ?? "User", // Dùng Role đầu tiên cho tương thích ngược
                Roles = roleNames, // <-- THÊM DANH SÁCH MỚI
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }
    }
}