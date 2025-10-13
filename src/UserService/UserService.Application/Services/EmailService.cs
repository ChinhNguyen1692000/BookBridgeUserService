using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

public class EmailService : IEmailService
{
    private readonly IConfiguration _config;

    public EmailService(IConfiguration config)
    {
        _config = config;
    }

    public async Task SendPasswordResetEmail(string toEmail, string otpCode)
    {
        var smtpHost = _config["Smtp:Host"];
        var smtpPort = int.Parse(_config["Smtp:Port"]);
        var smtpUser = _config["Smtp:Username"];
        var smtpPass = _config["Smtp:Password"];
        var fromEmail = _config["Smtp:From"];

        // var resetLink = $"https://yourfrontend.com/reset-password?token={resetToken}";

        var message = new MailMessage(fromEmail, toEmail)
        {
            Subject = "Đặt lại mật khẩu BookBridge",
            Body = $"Chào bạn,\n\nBạn vừa yêu cầu đặt lại mật khẩu. Nhập otp sau đây để tạo mật khẩu mới:\n{otpCode}\nMã sẽ hết hạn sau 5 phút",
            IsBodyHtml = false
        };

        using var client = new SmtpClient(smtpHost, smtpPort)
        {
            Credentials = new NetworkCredential(smtpUser, smtpPass),
            EnableSsl = true
        };

        await client.SendMailAsync(message);
    }

    public async Task SendTemporaryPasswordEmail(string toEmail, string otpCode)
    {
        var smtpHost = _config["Smtp:Host"];
        var smtpPort = int.Parse(_config["Smtp:Port"]);
        var smtpUser = _config["Smtp:Username"];
        var smtpPass = _config["Smtp:Password"];
        var fromEmail = _config["Smtp:From"];

        var message = new MailMessage(fromEmail, toEmail)
        {
            Subject = "Mật khẩu tạm thời BookBridge",
            Body = $"Chào bạn,\n\nMã OTP kích hoạt tài khoản của bạn là: {otpCode}\nMã sẽ hết hạn sau 5 phút.",
            IsBodyHtml = false
        };

        using var client = new SmtpClient(smtpHost, smtpPort)
        {
            Credentials = new NetworkCredential(smtpUser, smtpPass),
            EnableSsl = true
        };

        await client.SendMailAsync(message);
    }

    public async Task SendActivationOtpEmail(string toEmail, string otpCode)
    {
        var smtpHost = _config["Smtp:Host"];
        var smtpPort = int.Parse(_config["Smtp:Port"]);
        var smtpUser = _config["Smtp:Username"];
        var smtpPass = _config["Smtp:Password"];
        var fromEmail = _config["Smtp:From"];

        var message = new MailMessage(fromEmail, toEmail)
        {
            Subject = "Kích hoạt tài khoản BookBridge",
            Body = $"Chào bạn,\n\nMã OTP kích hoạt tài khoản của bạn là: {otpCode}\nMã sẽ hết hạn sau 5 phút.",
            IsBodyHtml = false
        };

        using var client = new SmtpClient(smtpHost, smtpPort)
        {
            Credentials = new NetworkCredential(smtpUser, smtpPass),
            EnableSsl = true
        };

        await client.SendMailAsync(message);
    }
}
