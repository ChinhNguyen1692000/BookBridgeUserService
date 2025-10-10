using UserService.Application.Interfaces;
using UserService.Application.Models;
using UserService.Domain.Entities;
using UserService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace UserService.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserDbContext _context;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly IEmailService _emailService;

        public AuthService(UserDbContext context, IPasswordHasher hasher, ITokenGenerator tokenGenerator, IEmailService emailService)
        {
            _context = context;
            _passwordHasher = hasher;
            _tokenGenerator = tokenGenerator;
            _emailService = emailService;
        }

        public async Task<AuthResponse> Register(RegisterRequest request)
        {
            if (request.Password != request.Repassword)
                throw new ArgumentException("Passwords do not match.");

            bool userExists = await _context.Users.AnyAsync(u => u.Email == request.Email || u.Username == request.Username);
            if (userExists)
                throw new InvalidOperationException("Email or Username already exists.");

            var passwordHash = _passwordHasher.HashPassword(request.Password);

            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = request.Username,
                Email = request.Email,
                Phone = request.Phone,
                PasswordHash = passwordHash,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);

            var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "User");
            if (defaultRole == null)
                throw new InvalidOperationException("Default role 'User' not found.");

            _context.UserRoles.Add(new UserRole
            {
                UserId = user.Id,
                RoleId = defaultRole.Id
            });

            await _context.SaveChangesAsync();

            var roles = await GetUserRoles(user.Id);
            return _tokenGenerator.GenerateToken(user, roles);
        }

        public async Task<AuthResponse> Login(LoginRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user == null)
                throw new UnauthorizedAccessException("Invalid credentials.");

            bool isPasswordValid = _passwordHasher.VerifyPassword(user.PasswordHash, request.Password);
            if (!isPasswordValid)
                throw new UnauthorizedAccessException("Invalid credentials.");

            var roles = await GetUserRoles(user.Id);
            return _tokenGenerator.GenerateToken(user, roles);
        }

        public async Task ForgetPassword(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return;

            var resetToken = Guid.NewGuid().ToString("N");

            var resetEntry = new PasswordResetToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Token = resetToken,
                ExpiryDate = DateTime.UtcNow.AddHours(2),
                IsUsed = false
            };

            _context.PasswordResetTokens.Add(resetEntry);
            await _context.SaveChangesAsync();

            await _emailService.SendPasswordResetEmail(user.Email, resetToken);
        }

        public async Task ResetPassword(string token, string newPassword)
        {
            var resetEntry = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.Token == token && t.ExpiryDate > DateTime.UtcNow && !t.IsUsed);

            if (resetEntry == null)
                throw new InvalidOperationException("Invalid or expired token.");

            var user = await _context.Users.FindAsync(resetEntry.UserId);
            if (user == null)
                throw new InvalidOperationException("User not found.");

            user.PasswordHash = _passwordHasher.HashPassword(newPassword);
            resetEntry.IsUsed = true;

            _context.Users.Update(user);
            _context.PasswordResetTokens.Update(resetEntry);

            await _context.SaveChangesAsync();
        }

        private async Task<List<string>> GetUserRoles(Guid userId)
        {
            return await _context.UserRoles
                .Where(ur => ur.UserId == userId)
                .Select(ur => ur.Role.RoleName)
                .ToListAsync();
        }

        public Task<AuthResponse> GoogleLogin(GoogleLoginRequest request)
        {
            throw new NotImplementedException("Google Login is configured but not yet implemented.");
        }
    }
}
