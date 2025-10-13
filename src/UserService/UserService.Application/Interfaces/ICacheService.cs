public interface ICacheService
{
    Task AddToBlacklistAsync(string jti, TimeSpan expiry);
    Task<bool> IsBlacklistedAsync(string jti);
}
