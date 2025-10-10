using System;

namespace UserService.Domain.Entities
{
    public class UserRole
    {
        // Khóa chính tổng hợp
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }

        
        // Navigation Properties
        public User User { get; set; } = default!; // Thiết lập quan hệ với User
        public Role Role { get; set; } = default!; // Thiết lập quan hệ với Role
    }
}