public interface IOTPService
{
    Task<string> GenerateAndStoreOtpAsync(Guid userId, OtpType type, int length = 6);
    Task<bool> ValidateOtpAsync(Guid userId, string otpCode, OtpType type);
}
