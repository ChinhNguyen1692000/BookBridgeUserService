using System;


namespace UserService.Domain.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; }
        public string? Phone { get; set; }
        public string Email { get; set; }
        public string? PasswordHash { get; set; }
        public DateTime CreatedAt { get; set; }
        // public string UserRole { get; set; }
        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
        // Thuộc tính mới để đánh dấu người dùng đăng ký qua Google
        public bool IsGoogleUser { get; set; } = false;
        // Thuộc tính mới để đánh dấu người dùng có kích hoạt hay không
        public bool IsActive { get; set; } = false;
        // Navigation property cho UserOtp
        public ICollection<UserOtp> UserOtps { get; set; } = new List<UserOtp>();
        // Navigation property cho PasswordResetToken
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();


    }
}