using System;

namespace UserService.Domain.Entities
{
    public class Role
    {
        public Guid Id { get; set; } 
        public string RoleName { get; set; } = default!;
        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    }
} 