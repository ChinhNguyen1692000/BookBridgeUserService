using UserService.Application.Interfaces;
using BCrypt.Net; // Cần cài đặt BCrypt.Net-Core

namespace UserService.Application.Services
{
    public class PasswordHasher : IPasswordHasher
    {
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public bool VerifyPassword(string hashedPassword, string providedPassword)
        {
            try
            {
                return BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword);
            }
            catch
            {
                return false; // Xử lý lỗi nếu hash không hợp lệ
            }
        }
    }
}