using System;


namespace UserService.Domain.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; }
        public string Phone { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public DateTime CreatedAt { get; set; }
        // public string UserRole { get; set; }
        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();

    }
}