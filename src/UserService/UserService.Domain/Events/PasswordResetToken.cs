using System;

namespace UserService.Domain.Entities
{
    public class PasswordResetToken
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string Token { get; set; }
        public DateTime ExpiryDate { get; set; }
        public bool IsUsed { get; set; } = false;

        // Navigation property (Optional, for easy access)
        // public User User { get; set; } 
    }
}