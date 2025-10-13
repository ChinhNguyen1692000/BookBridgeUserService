
using UserService.Domain.Entities;

public class UserOtp
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public User User { get; set; }

    public string OtpCode { get; set; }
    public DateTime Expiry { get; set; }
    public OtpType Type { get; set; } // Activation, ResetPassword
    public bool IsUsed { get; set; } = false; // Đánh dấu OTP đã được sử dụng hay chưa
}

public enum OtpType
{
    Activation,
    ResetPassword
}
