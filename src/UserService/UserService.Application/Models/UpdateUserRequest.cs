using System;

namespace UserService.Application.Models
{
    public class UpdateUserRequest
    {
        public string Username { get; set; }
        public string Phone { get; set; }
    }
}