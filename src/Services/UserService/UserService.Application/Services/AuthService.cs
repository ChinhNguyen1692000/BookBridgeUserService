using UserService.Application.Interfaces;
using UserService.Application.Models;
using UserService.Domain.Entities;
using UserService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Google.Apis.Auth;
using UserService.Application.Configurations;
using Microsoft.Extensions.Options;
using Common.Paging;
using UserService.Application.CustomExceptions;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging;
using System.Net.Mail;
using System.Net.Http.Headers;


namespace UserService.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserDbContext _context;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly IEmailService _emailService;
        private readonly GoogleAuthSettings _googleAuthSettings;
        private readonly IPasswordGenerator _passwordGenerator;
        private readonly IOTPService _otpService;
        private readonly ICacheService _cacheService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(UserDbContext context, IPasswordHasher hasher, ITokenGenerator tokenGenerator, IEmailService emailService,
         IOptions<GoogleAuthSettings> googleAuthOptions, IPasswordGenerator passwordGenerator, IOTPService otpService,
         ICacheService cacheService, ILogger<AuthService> logger)
        {
            _context = context;
            _passwordHasher = hasher;
            _tokenGenerator = tokenGenerator;
            _emailService = emailService;
            _googleAuthSettings = googleAuthOptions.Value;
            _passwordGenerator = passwordGenerator;
            _otpService = otpService;
            _cacheService = cacheService;
            _logger = logger;
        }

        // Get all users with pagination
        public async Task<PagedResult<User>> GetAllAsync(int pageNo, int pageSize)
        {
            var users = await _context.Users.ToListAsync();
            return PagedResult<User>.Create(users, pageNo, pageSize);
        }

        // Get user by ID
        public async Task<User> GetByIdAsync(Guid userId)
        {
            return await _context.Users.FindAsync(userId);
        }

        // This method handles user registration by validating input, checking for existing users, hashing the password, creating a new user, assigning a default role, and returning a JWT token.
        public async Task<RegisterResponse> Register(RegisterRequest request)
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

            // Gửi email kích hoạt
            var otpCode = await _otpService.GenerateAndStoreOtpAsync(user.Id, OtpType.Activation);
            await _emailService.SendActivationOtpEmail(user.Email, otpCode);

            var roles = await GetUserRoles(user.Id);
            var registerResponse = new RegisterResponse
            {
                Id = user.Id.ToString(),
                Username = user.Username,
                Email = user.Email,
                Roles = roles
            };
            return registerResponse;
        }


        // Kích hoạt tài khoản qua email
        public async Task<(bool Success, string Message)> ActiveEmailAccount(string otp, string email)
        {

            // Validate input
            if (string.IsNullOrWhiteSpace(otp) || otp.Length > 10)
                return (false, "Invalid OTP format.");

            // Check if user exists
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
                return (false, "Email does not exist.");
            if (user.IsActive)
                return (false, "Account is already active.");

            // Check if account is already active
            var isActiveAccount = await _context.Users
                .Where(u => u.Email == email && u.IsActive)
                .AnyAsync();
            if (isActiveAccount)
                return (false, "Account is already active.");

            // Find OTP record    
            var userOtp = await _context.UserOtps
                .Include(u => u.User)
                 .FirstOrDefaultAsync(u => u.OtpCode == otp
                              && u.Type == OtpType.Activation
                              && !u.IsUsed
                              && u.User.Email == email);

            if (userOtp == null)
                return (false, "OTP does not exist.");
            if (userOtp.IsUsed)
                return (false, "OTP has already been used.");
            if (userOtp.Expiry < DateTime.UtcNow)
                return (false, "OTP has expired.");

            // Activate user account
            userOtp.IsUsed = true;
            userOtp.User.IsActive = true;

            await _context.SaveChangesAsync();
            return (true, "Account activated successfully.");
        }


        // This method handles user login by validating credentials and generating a JWT token.
        public async Task<AuthResponse> Login(LoginRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                throw new ArgumentException("Email and password are required.");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user == null)
                throw new UnauthorizedAccessException("Email not found.");

            bool isPasswordValid = _passwordHasher.VerifyPassword(user.PasswordHash, request.Password);
            if (!isPasswordValid)
                throw new UnauthorizedAccessException("Password is incorrect.");

            // 2. Kiểm tra IsActive
            if (!user.IsActive)
            {
                // Gửi OTP kích hoạt
                var otpCode = await _otpService.GenerateAndStoreOtpAsync(user.Id, OtpType.Activation);
                await _emailService.SendActivationOtpEmail(user.Email, otpCode);

                throw new AccountNotActiveException("Account is not active. An activation OTP has been sent to your email.");
            }

            // Kiểm tra IsGoogleUser để xử lý cho lần sau login thường
            if (user.IsGoogleUser)
            {
                // Nếu user này có cờ Google Login nhưng lại đăng nhập bằng mật khẩu
                // => Mặc định cho phép, không cần thay đổi gì. Cờ IsGoogleUser chỉ để đánh dấu user đó CÓ THỂ login bằng Google.
            }

            // Trong AuthService.Login hoặc GoogleLogin trước khi tạo token mới

            // Kiểm tra xem user đã có Refresh Token nào chưa (tức là đã login từ trước và chưa logout)
            var activeTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == user.Id && !rt.IsRevoked && rt.Expiry > DateTime.UtcNow)
                .ToListAsync();

            if (activeTokens.Any())
            {
                throw new InvalidOperationException("User must logout before logging in again.");
            }


            // Tạo và lưu Refresh Token mới, trả về AccessToken/RefreshToken
            // return await _tokenGenerator.GenerateToken(user, await GetUserRoles(user.Id));

            var roles = await GetUserRoles(user.Id);
            return await _tokenGenerator.GenerateToken(user, roles);
        }

        // This method initiates the password reset process by generating a reset token and sending it via email.
        public async Task ForgetPassword(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return;

            try
            {
                // Gửi otp vao email
                var otpCode = await _otpService.GenerateAndStoreOtpAsync(user.Id, OtpType.ResetPassword);
                await _emailService.SendPasswordResetEmail(user.Email, otpCode);

                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Lỗi khi gửi mail quên mật khẩu cho {email}");
                throw;
            }
        }



        public async Task ResetPassword(string email, string otpCode, string newPassword, string confirmPassword)
        {
            // 1. Kiểm tra input cơ bản
            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentException("Email can't be empty.");

            if (string.IsNullOrWhiteSpace(newPassword) || string.IsNullOrWhiteSpace(confirmPassword))
                throw new ArgumentException("Password & Confirm Password can't be empty.");

            if (string.IsNullOrWhiteSpace(otpCode))
            {
                throw new ArgumentException("OTP can't be empty.");
            }

            if (newPassword != confirmPassword)
                throw new InvalidOperationException("Confirm Password not match.");


            // 2. Kiểm tra người dùng tồn tại
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                throw new InvalidOperationException("Email haven't registed in system yet.");

            // 3. Xác thực OTP
            var otpEntry = await _context.UserOtps.FirstOrDefaultAsync(o =>
                o.UserId == user.Id &&
                o.OtpCode == otpCode &&
                o.Type == OtpType.ResetPassword &&
                !o.IsUsed &&
                o.Expiry > DateTime.UtcNow);

            if (otpEntry == null)
                throw new InvalidOperationException("OTP not valid or it have expired.");

            // 4. Đổi mật khẩu
            user.PasswordHash = _passwordHasher.HashPassword(newPassword);
            otpEntry.IsUsed = true;

            _context.Users.Update(user);
            _context.UserOtps.Update(otpEntry);

            await _context.SaveChangesAsync();
        }



        // Helper method to get roles of a user
        private async Task<List<string>> GetUserRoles(Guid userId)
        {
            return await _context.UserRoles
                .Where(ur => ur.UserId == userId)
                .Select(ur => ur.Role.RoleName)
                .ToListAsync();
        }

        // This method handles Google login by validating the Google token, checking/creating the user in the database, and generating a JWT token.
        public async Task<AuthResponse> GoogleLogin(GoogleLoginRequest request)
        {
            // Lấy danh sách Accepted Audiences từ cấu hình
            var acceptedAudiences = _googleAuthSettings.AcceptedAudiences;

            // Xác thực token Google
            GoogleJsonWebSignature.Payload payload;
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = acceptedAudiences
                };

                payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings);
            }
            catch (Exception ex)
            {
                throw new UnauthorizedAccessException("Invalid Google token: " + ex.Message);
            }

            // Kiểm tra user trong DB
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == payload.Email);

            // Nếu chưa có, tạo user mới
            if (user == null)
            {
                // 1. Sinh mật khẩu ngẫu nhiên
                var randomPassword = _passwordGenerator.GenerateRandomPassword(); // Cần có IPasswordGenerator
                var hashedPassword = _passwordHasher.HashPassword(randomPassword);
                user = new User
                {
                    Id = Guid.NewGuid(),
                    Username = payload.Name ?? payload.Email.Split('@')[0],
                    Email = payload.Email,
                    Phone = null,
                    PasswordHash = hashedPassword, // Mật khẩu ngẫu nhiên
                    CreatedAt = DateTime.UtcNow,
                    IsGoogleUser = true, // Gắn cờ
                    IsActive = true // Kích hoạt luôn
                };

                // Thêm user mới vào DB
                _context.Users.Add(user);

                // Gán role mặc định
                var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "User");
                if (defaultRole != null)
                {
                    _context.UserRoles.Add(new UserRole
                    {
                        UserId = user.Id,
                        RoleId = defaultRole.Id
                    });
                }

                // Lưu thay đổi vào DB
                await _context.SaveChangesAsync();
                await _emailService.SendTemporaryPasswordEmail(user.Email, randomPassword);
            }
            else
            {
                // 4️ Nếu user đã tồn tại
                if (!user.IsGoogleUser)
                {
                    // User trước đó đăng ký bằng mật khẩu
                    // Option 1: buộc liên kết account trước khi login bằng Google
                    // throw new UnauthorizedAccessException("Account exists. Please login with password or link accounts.");

                    // Option 2: cho phép login, đánh dấu account này hỗ trợ Google
                    user.IsGoogleUser = true;
                    await _context.SaveChangesAsync();
                }

                if (!user.IsActive)
                {
                    user.IsActive = true; // kích hoạt account nếu trước đó chưa active
                    await _context.SaveChangesAsync();
                }
            }

            // Kiểm tra xem user đã có Refresh Token nào chưa (tức là đã login từ trước và chưa logout)
            var activeTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == user.Id && !rt.IsRevoked && rt.Expiry > DateTime.UtcNow)
                .ToListAsync();

            if (activeTokens.Any())
            {
                throw new InvalidOperationException("User must logout before logging in again.");
            }

            // Sinh token của hệ thống
            var roles = await GetUserRoles(user.Id);
            return await _tokenGenerator.GenerateToken(user, roles);
        }

        // Cập nhật username và phone number
        public async Task<string> UpdateUserNameAndPhoneNumberAsync(UpdateUserRequest request, Guid userId)
        {
            if (string.IsNullOrWhiteSpace(request.Username))
                throw new ArgumentException("Username không được để trống.");

            if (request.Username.Length > 100)
                throw new ArgumentException("Username quá dài.");

            if (!string.IsNullOrWhiteSpace(request.Phone) && request.Phone.Length > 20)
                throw new ArgumentException("Phone quá dài.");

            // Check trùng username (không tính chính user)
            var usernameExists = await _context.Users
                .AnyAsync(u => u.Username == request.Username && u.Id != userId);
            if (usernameExists)
                throw new ArgumentException("Username đã tồn tại.");

            // Check trùng phone (không tính chính user)
            if (!string.IsNullOrWhiteSpace(request.Phone))
            {
                var phoneExists = await _context.Users
                    .AnyAsync(u => u.Phone == request.Phone && u.Id != userId);
                if (phoneExists)
                    throw new ArgumentException("Phone đã tồn tại.");
            }

            // Lấy user hiện tại
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                throw new Exception("User không tồn tại");

            user.Username = request.Username;
            user.Phone = request.Phone;

            await _context.SaveChangesAsync();

            return "User info updated successfully.";
        }


        // Cập nhật mật khẩu người dùng
        public async Task<string> UpdateUserPasswordAsync(UpdateUserPasswordRequest request, Guid userId)
        {
            if (string.IsNullOrWhiteSpace(request.CurrentPassword))
                throw new ArgumentException("CurrentPassword is required.");

            if (string.IsNullOrWhiteSpace(request.Password))
                throw new ArgumentException("Password is required.");

            if (request.Password != request.Repassword)
                throw new ArgumentException("Password and Repassword do not match.");

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                throw new Exception("User does not exist.");

            // Xác thực mật khẩu hiện tại
            bool isCurrentPasswordValid = _passwordHasher.VerifyPassword(
            user.PasswordHash,        // hashedPassword (từ DB)
            request.CurrentPassword   // providedPassword (từ request)
            );

            if (!isCurrentPasswordValid)
            {
                // Ném lỗi để Controller bắt và trả về 400 Bad Request
                throw new ArgumentException("Current password is incorrect.");
            }

            user.PasswordHash = _passwordHasher.HashPassword(request.Password);
            await _context.SaveChangesAsync();

            return "Password updated successfully.";
        }

        // Đăng xuất: thu hồi tất cả Refresh Token của user 
        public async Task LogoutAsync(Guid userId, string jtiClaim)
        {
            var tokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId)
                .ToListAsync();

            foreach (var t in tokens)
            {
                t.IsRevoked = true;
            }

            await _context.SaveChangesAsync();

            // Đưa access token hiện tại vào blacklist Redis
            var accessTokenExpiry = TimeSpan.FromHours(2);
            await _cacheService.AddToBlacklistAsync(jtiClaim, accessTokenExpiry);
        }


        // Làm mới token: kiểm tra Refresh Token, nếu hợp lệ thì tạo Access Token mới
        public async Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request, string oldAccessToken)
        {
            var refreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

            if (refreshToken == null || refreshToken.IsRevoked || refreshToken.Expiry < DateTime.UtcNow)
            {
                throw new UnauthorizedAccessException("Invalid or expired refresh token.");
            }

            // Tạo access token mới
            var userId = refreshToken.UserId;
            refreshToken.IsRevoked = true;
            await _context.SaveChangesAsync();

            var roles = await GetUserRoles(refreshToken.UserId);
            var authResponse = await _tokenGenerator.GenerateToken(refreshToken.User, roles);

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadJwtToken(oldAccessToken);
                var oldJti = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
                await _cacheService.AddToBlacklistAsync(oldJti, TimeSpan.FromHours(2));
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Could not blacklist old access token during refresh: {ex.Message}");
            }

            return authResponse;
        }
    }
}
