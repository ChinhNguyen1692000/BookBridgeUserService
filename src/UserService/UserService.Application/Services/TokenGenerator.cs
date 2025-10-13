using UserService.Application.Interfaces;
using UserService.Application.Models;
using UserService.Domain.Entities;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using UserService.Infrastructure.Data; // Cần config
namespace UserService.Application.Services
{
    public class TokenGenerator : ITokenGenerator
    {
        private readonly IConfiguration _config;
        private readonly UserDbContext _context;
        public TokenGenerator(IConfiguration config, UserDbContext context)
        {
            _config = config;
            _context = context;
        }

        // Thêm tham số roleNames
        async public Task<AuthResponse> GenerateToken(User user, List<string> roleNames)
        {
            // Tạo token handler
            var tokenHandler = new JwtSecurityTokenHandler();

            // Lấy key từ config
            var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]); // Lấy key từ config

            // Lấy issuer và audience từ config
            var jwtIssuer = _config["Jwt:Issuer"];
            var jwtAudience = _config["Jwt:Audience"];

            // Tạo jti (unique identifier for the token)
            var jti = Guid.NewGuid().ToString(); // Tạo ID duy nhất cho token này


            // Tạo claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), // Sử dụng Id làm NameIdentifier
                new Claim(ClaimTypes.Email, user.Email), // Thêm email vào claims
                // new Claim(ClaimTypes.Role, user.UserRole)
                new Claim(JwtRegisteredClaimNames.Jti, jti) // Thêm jti vào claims
            };

            // Thêm tất cả các role vào claims
            foreach (var roleName in roleNames)
            {
                claims.Add(new Claim(ClaimTypes.Role, roleName)); // <-- Thêm nhiều lần
            }



            // Access token 2 giờ
            var accessTokenExpiry = DateTime.UtcNow.AddHours(2);

            // Refresh token 7 ngày
            var refreshTokenExpiry = DateTime.UtcNow.AddDays(7);

            // Cấu hình token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = accessTokenExpiry,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = jwtIssuer,
                Audience = jwtAudience

            };

            // Tạo token
            var token = tokenHandler.CreateToken(tokenDescriptor);
            // Chuyển token thành chuỗi
            var accessToken = tokenHandler.WriteToken(token);

            // Tạo refresh token và lưu DB (giả sử bạn có DbSet<RefreshToken> trong DbContext)
            var refreshTokenObj = new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                UserId = user.Id,
                Expiry = refreshTokenExpiry
            };

            _context.RefreshTokens.Add(refreshTokenObj);
            await _context.SaveChangesAsync();

            // Trả về AuthResponse với danh sách Roles
            return new AuthResponse
            {
                Id = user.Id.ToString(), // Chuyển Guid sang string
                Username = user.Username,
                Email = user.Email,
                // Role = roleNames.FirstOrDefault() ?? "User", // Dùng Role đầu tiên cho tương thích ngược
                Roles = roleNames, // <-- THÊM DANH SÁCH MỚI
                AccessToken = accessToken,
                RefreshToken = refreshTokenObj.Token
            };
        }
    }
}