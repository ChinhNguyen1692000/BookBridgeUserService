using System.Text;
using System.Text.Json;
using Google.Apis.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NetHttpClientFactory = System.Net.Http.IHttpClientFactory;



public class EmailService : IEmailService
{
    private readonly IConfiguration _config;
    private readonly ILogger<EmailService> _logger;
    private readonly NetHttpClientFactory _httpClientFactory;

    public EmailService(IConfiguration config, ILogger<EmailService> logger, NetHttpClientFactory httpClientFactory)
    {
        _config = config;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    private async Task SendEmailViaResend(string toEmail, string subject, string htmlBody)
    {
        var apiKey = _config["Resend:ApiKey"];
        var fromEmail = _config["Resend:From"];

        var client = _httpClientFactory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);

        var payload = new
        {
            from = fromEmail,
            to = toEmail,
            subject = subject,
            html = htmlBody
        };

        var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        var response = await client.PostAsync("https://api.resend.com/emails", content);

        var result = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Resend API error: {StatusCode} - {Response}", response.StatusCode, result);
            throw new Exception($"Resend failed: {result}");
        }

        _logger.LogInformation("Email sent to {ToEmail} via Resend.", toEmail);
    }

    public async Task SendPasswordResetEmail(string toEmail, string otpCode)
    {
        var subject = "Đặt lại mật khẩu BookBridge";
        var html = $"<p>Chào bạn,</p><p>Bạn vừa yêu cầu đặt lại mật khẩu. Mã OTP của bạn là:</p><h2>{otpCode}</h2><p>Mã sẽ hết hạn sau 5 phút.</p>";
        await SendEmailViaResend(toEmail, subject, html);
    }

    public async Task SendTemporaryPasswordEmail(string toEmail, string otpCode)
    {
        var subject = "Mật khẩu tạm thời BookBridge";
        var html = $"<p>Chào bạn,</p><p>Mã OTP kích hoạt tài khoản của bạn là:</p><h2>{otpCode}</h2><p>Mã sẽ hết hạn sau 5 phút.</p>";
        await SendEmailViaResend(toEmail, subject, html);
    }

    public async Task SendActivationOtpEmail(string toEmail, string otpCode)
    {
        var subject = "Kích hoạt tài khoản BookBridge";
        var html = $"<p>Chào bạn,</p><p>Mã OTP kích hoạt tài khoản của bạn là:</p><h2>{otpCode}</h2><p>Mã sẽ hết hạn sau 5 phút.</p>";
        await SendEmailViaResend(toEmail, subject, html);
    }
}
