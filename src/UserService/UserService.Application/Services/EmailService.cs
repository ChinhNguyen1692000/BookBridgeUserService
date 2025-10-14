using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

public class EmailService : IEmailService
{
    private readonly IConfiguration _config;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IConfiguration config, ILogger<EmailService> logger)
    {
        _config = config;
        _logger = logger; // Gán Logger
    }

    public async Task SendPasswordResetEmail(string toEmail, string otpCode)
    {
        var smtpHost = _config["Smtp:Host"];
        var smtpPort = int.Parse(_config["Smtp:Port"]);
        var smtpUser = _config["Smtp:Username"];
        var smtpPass = _config["Smtp:Password"];
        var fromEmail = _config["Smtp:From"];

        _logger.LogInformation("Attempting to send activation email to {ToEmail}. Host: {SmtpHost}:{SmtpPort}. User: {SmtpUser}",
                               toEmail, smtpHost, smtpPort, smtpUser);

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

        try
        {
            await client.SendMailAsync(message);
            _logger.LogInformation("Successfully sent activation email to {ToEmail}.", toEmail);
        }
        catch (SmtpException ex)
        {
            // **Log lỗi SMTP chi tiết**
            // Lỗi xác thực, lỗi server, lỗi kết nối...
            _logger.LogError(ex, "SMTP Error (Status Code: {StatusCode}) when sending email to {ToEmail}. Check App Password and SMTP config.",
                             ex.StatusCode, toEmail);
            // Re-throw để khối catch trong UserService xử lý Rollback
            throw new Exception($"Failed to send email to {toEmail} due to SMTP configuration or network error.", ex);
        }
        catch (Exception ex)
        {
            // Log các lỗi khác (Parsing, Configuration...)
            _logger.LogError(ex, "General Error when sending email to {ToEmail}.", toEmail);
            throw;
        }
    }

    public async Task SendTemporaryPasswordEmail(string toEmail, string otpCode)
    {
        var smtpHost = _config["Smtp:Host"];
        var smtpPort = int.Parse(_config["Smtp:Port"]);
        var smtpUser = _config["Smtp:Username"];
        var smtpPass = _config["Smtp:Password"];
        var fromEmail = _config["Smtp:From"];

        _logger.LogInformation("Attempting to send activation email to {ToEmail}. Host: {SmtpHost}:{SmtpPort}. User: {SmtpUser}",
                               toEmail, smtpHost, smtpPort, smtpUser);

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

        try
        {
            await client.SendMailAsync(message);
            _logger.LogInformation("Successfully sent activation email to {ToEmail}.", toEmail);
        }
        catch (SmtpException ex)
        {
            // **Log lỗi SMTP chi tiết**
            // Lỗi xác thực, lỗi server, lỗi kết nối...
            _logger.LogError(ex, "SMTP Error (Status Code: {StatusCode}) when sending email to {ToEmail}. Check App Password and SMTP config.",
                             ex.StatusCode, toEmail);
            // Re-throw để khối catch trong UserService xử lý Rollback
            throw new Exception($"Failed to send email to {toEmail} due to SMTP configuration or network error.", ex);
        }
        catch (Exception ex)
        {
            // Log các lỗi khác (Parsing, Configuration...)
            _logger.LogError(ex, "General Error when sending email to {ToEmail}.", toEmail);
            throw;
        }
    }

    public async Task SendActivationOtpEmail(string toEmail, string otpCode)
    {
        var smtpHost = _config["Smtp:Host"];
        var smtpPort = int.Parse(_config["Smtp:Port"]);
        var smtpUser = _config["Smtp:Username"];
        var smtpPass = _config["Smtp:Password"];
        var fromEmail = _config["Smtp:From"];

        _logger.LogInformation("Attempting to send activation email to {ToEmail}. Host: {SmtpHost}:{SmtpPort}. User: {SmtpUser}",
                               toEmail, smtpHost, smtpPort, smtpUser);

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

        try
        {
            await client.SendMailAsync(message);
            _logger.LogInformation("Successfully sent activation email to {ToEmail}.", toEmail);
        }
        catch (SmtpException ex)
        {
            // **Log lỗi SMTP chi tiết**
            // Lỗi xác thực, lỗi server, lỗi kết nối...
            _logger.LogError(ex, "SMTP Error (Status Code: {StatusCode}) when sending email to {ToEmail}. Check App Password and SMTP config.",
                             ex.StatusCode, toEmail);
            // Re-throw để khối catch trong UserService xử lý Rollback
            throw new Exception($"Failed to send email to {toEmail} due to SMTP configuration or network error.", ex);
        }
        catch (Exception ex)
        {
            // Log các lỗi khác (Parsing, Configuration...)
            _logger.LogError(ex, "General Error when sending email to {ToEmail}.", toEmail);
            throw;
        }
    }
}
