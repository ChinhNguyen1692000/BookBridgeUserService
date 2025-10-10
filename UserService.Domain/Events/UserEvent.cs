using System;

namespace UserService.Domain.Events
{
    public class UserEvent
    {
        public Guid Id { get; set; }
        public DateTime Timestamp { get; set; }
        public Guid UserId { get; set; }
        public string Email { get; set; }
    }
}