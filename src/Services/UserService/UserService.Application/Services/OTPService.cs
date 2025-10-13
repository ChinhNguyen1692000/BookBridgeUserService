using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using UserService.Domain.Entities;
using UserService.Infrastructure.Data;

public class OTPService : IOTPService
{
    private readonly UserDbContext _context;

    public OTPService(UserDbContext context)
    {
        _context = context;
    }

    public async Task<string> GenerateAndStoreOtpAsync(Guid userId, OtpType type, int length = 6)
    {
        var random = new Random();
        var otp = string.Concat(Enumerable.Range(0, length).Select(_ => random.Next(0, 10)));

        var userOtp = new UserOtp
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            OtpCode = otp,
            Type = type,
            IsUsed = false,
            Expiry = DateTime.UtcNow.AddMinutes(5)
        };

        _context.UserOtps.Add(userOtp);
        await _context.SaveChangesAsync();

        return otp;
    }

    public async Task<bool> ValidateOtpAsync(Guid userId, string otpCode, OtpType type)
    {
        var otp = await _context.UserOtps
            .Where(u => u.UserId == userId && u.Type == type && !u.IsUsed)
            .OrderByDescending(u => u.Expiry)
            .FirstOrDefaultAsync();

        if (otp == null) return false;
        if (otp.Expiry < DateTime.UtcNow) return false;
        if (otp.OtpCode != otpCode) return false;

        otp.IsUsed = true;
        await _context.SaveChangesAsync();
        return true;
    }
}
