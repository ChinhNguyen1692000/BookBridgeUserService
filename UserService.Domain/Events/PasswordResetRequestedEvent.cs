using System;
public class PasswordResetRequestedEvent
{
    public Guid UserId { get; set; }
    public string Email { get; set; }
    public string ResetToken { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}