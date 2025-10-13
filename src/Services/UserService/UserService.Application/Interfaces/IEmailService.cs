public interface IEmailService
{
    // Thêm method mới cho reset mật khẩu
    Task SendPasswordResetEmail(string toEmail, string resetToken);

    // Thêm method mới cho gửi mật khẩu tạm thời
    Task SendTemporaryPasswordEmail(string toEmail, string tempPassword);
    
    // Thêm method mới cho gửi mã OTP kích hoạt tài khoản
    Task SendActivationOtpEmail(string toEmail, string otpCode);
}
