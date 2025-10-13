using System;

namespace UserService.Application.Models
{
    public class ResetRequest
    {
        public string Email { get; set; }
        public string Otp { get; set; }
        public string Password { get; set; }
        public string Repassword { get; set; }
        
    }
}