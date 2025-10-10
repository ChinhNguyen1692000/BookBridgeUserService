public interface IEmailService
{
    Task SendPasswordResetEmail(string toEmail, string resetToken);
}
