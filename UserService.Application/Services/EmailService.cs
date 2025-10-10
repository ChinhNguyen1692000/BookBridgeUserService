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

    public async Task SendPasswordResetEmail(string toEmail, string resetToken)
    {
        var smtpHost = _config["Smtp:Host"];
        var smtpPort = int.Parse(_config["Smtp:Port"]);
        var smtpUser = _config["Smtp:Username"];
        var smtpPass = _config["Smtp:Password"];
        var fromEmail = _config["Smtp:From"];

        var resetLink = $"https://yourfrontend.com/reset-password?token={resetToken}";

        var message = new MailMessage(fromEmail, toEmail)
        {
            Subject = "Đặt lại mật khẩu BookBridge",
            Body = $"Chào bạn,\n\nBạn vừa yêu cầu đặt lại mật khẩu. Nhấn vào link sau để tiếp tục:\n{resetLink}\n\nLink sẽ hết hạn sau 2 giờ.",
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
