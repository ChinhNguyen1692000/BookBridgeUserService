using StackExchange.Redis;
using System;
using System.Threading.Tasks;

public class RedisCacheService : ICacheService
{
    private readonly IDatabase _db;

    public RedisCacheService(IConnectionMultiplexer redis)
    {
        _db = redis.GetDatabase();
    }

    public async Task AddToBlacklistAsync(string jti, TimeSpan expiry)
    {
        // Lưu key với TTL (thời gian sống)
        await _db.StringSetAsync($"blacklist:{jti}", "revoked", expiry);
    }

    public async Task<bool> IsBlacklistedAsync(string jti)
    {
        return await _db.KeyExistsAsync($"blacklist:{jti}");
    }
}
