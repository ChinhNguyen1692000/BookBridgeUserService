// DTO cho bước 1: Chỉ nhập email
using System.ComponentModel.DataAnnotations;

public class CheckEmailRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}

// DTO cho bước 2: Đăng ký đầy đủ (có thêm OtpCode)
public class RegisterRequest
{
    [Required]
    public string Username { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    // Giả sử có thêm Phone như trong code cũ
    public string Phone { get; set; }

    [Required]
    public string Password { get; set; }

    [Required]
    public string Repassword { get; set; }

    [Required]
    public string OtpCode { get; set; } // Thêm trường OTP
}