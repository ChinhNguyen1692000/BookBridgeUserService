using System;

namespace UserService.Application.Models
{
    public class UpdateUserInforResponse
    {
        public Guid Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string Phone{ get; set; }
        public List<string> Roles { get; set; }
    }
}