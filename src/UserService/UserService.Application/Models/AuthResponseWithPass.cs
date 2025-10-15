using System;

namespace UserService.Application.Models
{
    public class AuthResponseWithPass
    {
        public string Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public List<string> Roles { get; set; }
        public string TempPassword{ get; set; }
    }
}