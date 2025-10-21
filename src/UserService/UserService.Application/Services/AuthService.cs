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
using Microsoft.EntityFrameworkCore.Metadata;


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

        public async Task<PagedResult<User>> GetAllAsync(int pageNo, int pageSize)
        {
            // 1. Lấy TỔNG SỐ LƯỢNG bản ghi (Dùng CountAsync() để chỉ đếm, không tải dữ liệu)
            var totalRecords = await _context.Users.CountAsync();

            // 2. PHÂN TRANG: Áp dụng Skip và Take trên database (IQueryable)
            var usersQuery = _context.Users
                // Thêm Include() nếu bạn cần tải Roles cùng lúc (Eager Loading)
                // .Include(u => u.UserRoles) 
                .Skip((pageNo - 1) * pageSize)
                .Take(pageSize);

            var users = await usersQuery.ToListAsync(); // Chỉ tải các bản ghi của trang hiện tại

            // 3. Xử lý dữ liệu sau khi truy vấn
            foreach (var user in users)
            {
                // Ẩn mật khẩu
                user.PasswordHash = "**********";
            }

            // 4. Trả về kết quả phân trang bằng hàm Create MỚI
            // Cung cấp 4 tham số: users, pageNo, pageSize, totalRecords
            return PagedResult<User>.Create(users, pageNo, pageSize, totalRecords);
        }

        // Get user by ID/ Get user by ID
        public async Task<GetUserByIdResponse> GetByIdAsync(Guid userId)
        {
            var user = await _context.Users
                .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                .SingleOrDefaultAsync(u => u.Id == userId);

            if (user == null) return null;

            // Ẩn mật khẩu
            user.PasswordHash = "**********";

            // Map sang DTO
            var response = new GetUserByIdResponse
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Phone = user.Phone,
                PasswordHash = user.PasswordHash,
                CreatedAt = user.CreatedAt,
                IsGoogleUser = user.IsGoogleUser,
                IsActive = user.IsActive,
                UserOtps = user.UserOtps,
                RefreshTokens = user.RefreshTokens,
                Roles = user.UserRoles
                            .Select(ur => new UserRoleDto
                            {
                                RoleId = ur.RoleId,
                                RoleName = ur.Role.RoleName
                            })
                            .ToList()
            };

            return response;
        }

        public async Task<string> DeleteUserAsync(Guid userId)
        {
            var userToDelete = await _context.Users
                .SingleOrDefaultAsync(u => u.Id == userId);

            if (userToDelete == null)
            {
                // Giả định NotFoundException đã được định nghĩa
                throw new NotFoundException($"Người dùng với ID '{userId}' không tồn tại.");
            }

            // **KHÔNG CẦN** xóa thủ công UserRoles, RefreshTokens, UserOTPs.
            // Entity Framework Core/Database sẽ tự làm việc này nhờ OnDelete(DeleteBehavior.Cascade).

            _context.Users.Remove(userToDelete);
            await _context.SaveChangesAsync(); // Việc xóa tầng xảy ra tại đây.

            return $"Người dùng '{userToDelete.Email}' và tất cả dữ liệu liên quan đã được xóa thành công.";
        }


        public async Task<RegisterResponse> Register(RegisterRequest request)
        {
            // 1. Validation cơ bản
            if (request.Password != request.Repassword)
                throw new ArgumentException("Passwords do not match.");

            // 2. Tìm User TẠM đã tạo ở bước 1
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
                throw new InvalidOperationException("Registration process not started. Please check email first.");

            if (user.IsActive)
                throw new InvalidOperationException("Account is already active. Please login");

            // 3. Kiểm tra trùng lặp cho các trường còn lại
            if (string.IsNullOrWhiteSpace(request.Username))
                throw new InvalidOperationException("Username is required.");

            if (!string.IsNullOrWhiteSpace(request.Phone) && await _context.Users.AnyAsync(u => u.Phone == request.Phone && u.Id != user.Id))
                throw new InvalidOperationException("Phone number already exists.");


            // 4. Kiểm tra và vô hiệu hóa OTP (thay thế cho ActiveEmailAccount cũ)
            var userOtp = await _context.UserOtps
                 .FirstOrDefaultAsync(u => u.OtpCode == request.OtpCode
                                 && u.Type == OtpType.Activation
                                 && !u.IsUsed
                                 && u.UserId == user.Id); // Quan trọng: OTP phải khớp với User tạm

            if (userOtp == null)
                throw new InvalidOperationException("Invalid or non-existent OTP.");
            if (userOtp.Expiry < DateTime.UtcNow)
                throw new InvalidOperationException("OTP has expired.");

            // 5. BẮT ĐẦU TRANSACTION
            var strategy = _context.Database.CreateExecutionStrategy();
            RegisterResponse registerResponse = null;

            await strategy.ExecuteAsync(async () =>
            {
                using var transaction = await _context.Database.BeginTransactionAsync();

                try
                {
                    // 6. Cập nhật thông tin User TẠM
                    var passwordHash = _passwordHasher.HashPassword(request.Password);

                    user.Username = request.Username;
                    user.Phone = request.Phone;
                    user.PasswordHash = passwordHash;
                    user.IsActive = true; // Kích hoạt tài khoản
                    user.IsGoogleUser = false;

                    _context.Users.Update(user);

                    // 7. Vô hiệu hóa OTP
                    userOtp.IsUsed = true;
                    _context.UserOtps.Update(userOtp);

                    // 9. Lưu thay đổi và Commit Transaction
                    await _context.SaveChangesAsync();
                    await transaction.CommitAsync();

                    // 10. Chuẩn bị Response
                    var roles = await GetUserRoles(user.Id); // Giả định có phương thức này
                    registerResponse = new RegisterResponse
                    {
                        Id = user.Id.ToString(),
                        Username = user.Username,
                        Email = user.Email,
                        Roles = roles
                    };
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    _logger.LogError(ex, "Registration failed for user {Email}. Transaction rolled back.", request.Email);
                    throw;
                }
            });

            return registerResponse;
        }



        public async Task<(bool Success, string Message)> ActiveSellerAccount(Guid userId)
        {
            try
            {
                // 1. Check user exists
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                    return (false, "User not found.");

                // 2. Find Seller role
                var sellerRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "Seller");
                if (sellerRole == null)
                    return (false, "Role 'Seller' not found in system.");

                // 3. If already seller -> done
                var alreadySeller = await _context.UserRoles
                    .AnyAsync(ur => ur.UserId == userId && ur.RoleId == sellerRole.Id);
                if (alreadySeller)
                    return (false, "User is already a seller.");

                // 4. Optionally ensure user is Buyer (business rule from your controller attribute)
                var buyerRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "Buyer");
                if (buyerRole != null)
                {
                    var isBuyer = await _context.UserRoles
                        .AnyAsync(ur => ur.UserId == userId && ur.RoleId == buyerRole.Id);
                    if (!isBuyer)
                        return (false, "Only users with Buyer role can activate seller account.");
                }
                // if buyerRole == null we skip this check (depends on your system)

                // 5. Add Seller role
                _context.UserRoles.Add(new UserRole
                {
                    UserId = userId,
                    RoleId = sellerRole.Id
                });

                await _context.SaveChangesAsync();

                return (true, "Seller account activated successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error activating seller account for user {UserId}", userId);
                return (false, "Internal server error while activating seller account.");
            }
        }



        // // Kích hoạt tài khoản qua email
        // public async Task<(bool Success, string Message)> ActiveEmailAccount(string otp, string email)
        // {

        //     // Validate input
        //     if (string.IsNullOrWhiteSpace(otp) || otp.Length > 10)
        //         return (false, "Invalid OTP format.");

        //     // Check if user exists
        //     var user = await _context.Users
        //         .FirstOrDefaultAsync(u => u.Email == email);

        //     if (user == null)
        //         return (false, "Email does not exist.");
        //     if (user.IsActive)
        //         return (false, "Account is already active.");

        //     // Check if account is already active
        //     var isActiveAccount = await _context.Users
        //         .Where(u => u.Email == email && u.IsActive)
        //         .AnyAsync();
        //     if (isActiveAccount)
        //         return (false, "Account is already active.");

        //     // Find OTP record    
        //     var userOtp = await _context.UserOtps
        //         .Include(u => u.User)
        //          .FirstOrDefaultAsync(u => u.OtpCode == otp
        //                       && u.Type == OtpType.Activation
        //                       && !u.IsUsed
        //                       && u.User.Email == email);

        //     if (userOtp == null)
        //         return (false, "OTP does not exist.");
        //     if (userOtp.IsUsed)
        //         return (false, "OTP has already been used.");
        //     if (userOtp.Expiry < DateTime.UtcNow)
        //         return (false, "OTP has expired.");

        //     // Activate user account
        //     userOtp.IsUsed = true;
        //     userOtp.User.IsActive = true;

        //     await _context.SaveChangesAsync();
        //     return (true, "Account activated successfully.");
        // }

        public async Task<RegisterResponse> CheckEmailForRegistration(string email)
        {
            // 1. Kiểm tra email đã active chưa
            var existingActiveUser = await _context.Users
                .AnyAsync(u => u.Email == email && u.IsActive);
            if (existingActiveUser)
                throw new InvalidOperationException("Email address already exists and is active. Please log in.");

            // 2. Kiểm tra user tạm (chưa active)
            var tempUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email && !u.IsActive);

            if (tempUser != null)
            {
                // Xóa OTP cũ chưa sử dụng của user này
                var oldOtps = await _context.UserOtps
                    .Where(o => o.UserId == tempUser.Id && o.Type == OtpType.Activation && !o.IsUsed)
                    .ToListAsync();

                _context.UserOtps.RemoveRange(oldOtps);
                await _context.SaveChangesAsync();
            }
            else
            {
                // Nếu chưa có user tạm → tạo user tạm
                tempUser = new User
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    Username = "Justin",
                    CreatedAt = DateTime.UtcNow,
                    IsActive = false,
                    IsGoogleUser = false
                };
                _context.Users.Add(tempUser);

                var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "Buyer");
                if (defaultRole == null)
                    throw new InvalidOperationException("Default role 'User' not found.");

                _context.UserRoles.Add(new UserRole
                {
                    UserId = tempUser.Id,
                    RoleId = defaultRole.Id
                });

                await _context.SaveChangesAsync();
            }

            // 3. Tạo OTP mới
            var otpCode = await _otpService.GenerateAndStoreOtpAsync(tempUser.Id, OtpType.Activation);
            // Gửi OTP kích hoạt
            await _emailService.SendActivationOtpEmail(tempUser.Email, otpCode);

            var roles = await GetUserRoles(tempUser.Id);
            var registerResponse = new RegisterResponse
            {
                Id = tempUser.Id.ToString(),
                Username = tempUser.Username,
                Email = tempUser.Email,
                Roles = roles,
            };


            return registerResponse;
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

            // Kiểm tra xem user đã có Refresh Token nào chưa (tức là đã login từ trước và chưa logout)
            var activeTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == user.Id && !rt.IsRevoked && rt.Expiry > DateTime.UtcNow)
                .ToListAsync();

            var roles = await GetUserRoles(user.Id);
            return await _tokenGenerator.GenerateToken(user, roles);
        }

        // This method initiates the password reset process by generating a reset token and sending it via email.
        public async Task<string> ForgetPassword(string email)
        {
            // 1. Kiểm tra người dùng tồn tại
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

            // Nếu user == null thì ném exception để Controller bắt và trả về lỗi
            if (user == null)
                throw new InvalidOperationException("Email chưa được đăng ký trong hệ thống."); // 👈 Thay đổi ở đây

            try
            {
                // 2. Tạo và lưu OTP
                // Giả định _otpService.GenerateAndStoreOtpAsync trả về string OTP
                var otpCode = await _otpService.GenerateAndStoreOtpAsync(user.Id, OtpType.ResetPassword);

                // **BỎ QUA:** Không gửi email nữa, nên loại bỏ dòng này
                await _emailService.SendPasswordResetEmail(user.Email, otpCode);

                await _context.SaveChangesAsync();

                // 3. Trả về OTP cho Controller
                return otpCode; // 👈 Thay đổi ở đây
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Lỗi khi tạo OTP quên mật khẩu cho {email}");
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
        public async Task<AuthResponseWithPass> GoogleLogin(GoogleLoginRequest request)
        {
            // Lấy danh sách Accepted Audiences từ cấu hình
            var acceptedAudiences = _googleAuthSettings.AcceptedAudiences;
            if (acceptedAudiences == null || !acceptedAudiences.Any())
            {
                _logger.LogError("GoogleAuth:AcceptedAudiences is not configured correctly.");
                throw new InvalidOperationException("Google login configuration error.");
            }

            // 1. Xác thực token Google
            GoogleJsonWebSignature.Payload payload;
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = acceptedAudiences // Client IDs đã được chấp nhận
                };

                payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings);
            }
            catch (Exception ex)
            {
                // FIX: Logging detail simplified since IPAddress is not on the request model
                _logger.LogError(ex, "Invalid Google token.");
                throw new UnauthorizedAccessException("Invalid Google token: " + ex.Message);
            }

            // 2. Kiểm tra user trong DB
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == payload.Email);

            // Temporary variable to hold the newly generated password if a new account is created
            string newRandomPassword = null;

            // 3. Nếu chưa có, tạo user mới
            if (user == null)
            {
                // 3.1. Sinh mật khẩu ngẫu nhiên và hash
                newRandomPassword = _passwordGenerator.GenerateRandomPassword();
                var hashedPassword = _passwordHasher.HashPassword(newRandomPassword);

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

                // 3.2. Gán role mặc định ("Buyer")
                var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleName == "Buyer");
                if (defaultRole == null)
                    throw new InvalidOperationException("Default role 'Buyer' not found.");

                _context.UserRoles.Add(new UserRole
                {
                    UserId = user.Id,
                    RoleId = defaultRole.Id
                });

                // 3.3. Thêm user mới vào DB
                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                _logger.LogInformation("New user created via Google login: {Email}", user.Email);
            }
            else
            {
                // 4. Nếu user đã tồn tại
                if (!user.IsActive)
                {
                    // For Google login, it's safer to just log in, as Google verified the email.
                    // If you have a separate activation flow, you might throw an exception here.
                    // Here, we'll ensure they are active.
                    user.IsActive = true;
                }

                // Cập nhật cờ IsGoogleUser nếu user này đã tồn tại nhưng chưa login bằng Google bao giờ
                if (!user.IsGoogleUser)
                {
                    user.IsGoogleUser = true;
                }

                // Save any changes (like IsActive or IsGoogleUser flag update)
                if (_context.Entry(user).State == EntityState.Modified)
                {
                    _context.Users.Update(user);
                    await _context.SaveChangesAsync();
                }
            }

            // 5. Tạo token và response
            var roles = await GetUserRoles(user.Id);
            var authResponse = await _tokenGenerator.GenerateToken(user, roles);

            // 6. Trả về AuthResponseWithPass
            return new AuthResponseWithPass
            {
                AccessToken = authResponse.AccessToken,
                RefreshToken = authResponse.RefreshToken,
                Id = user.Id.ToString(),
                Username = user.Username,
                Email = user.Email,
                Roles = roles,
                TempPassword = newRandomPassword // Trả về password chỉ khi tạo mới
            };
        }



        // Cập nhật username và phone number
        public async Task<UpdateUserInforResponse> UpdateUserNameAndPhoneNumberAsync(UpdateUserRequest request, Guid userId)
        {
            // --- 1. Validation ---
            if (string.IsNullOrWhiteSpace(request.Username))
                throw new ArgumentException("Username không được để trống.");

            if (request.Username.Length > 100)
                throw new ArgumentException("Username quá dài.");

            if (!string.IsNullOrWhiteSpace(request.Phone) && request.Phone.Length > 20)
                throw new ArgumentException("Phone quá dài.");

            // (Giữ lại logic check trùng phone như code gốc của bạn)
            if (!string.IsNullOrWhiteSpace(request.Phone))
            {
                var phoneExists = await _context.Users
                    .AnyAsync(u => u.Phone == request.Phone && u.Id != userId);
                if (phoneExists)
                    throw new ArgumentException("Phone đã tồn tại.");
            }

            // --- 2. Lấy User ---
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                throw new Exception("User không tồn tại");

            // --- 3. GÁN GIÁ TRỊ MỚI (PHẦN BỊ THIẾU/LỖI) ---
            // Gán giá trị Username mới
            user.Username = request.Username;

            // Gán giá trị Phone mới (chỉ khi có giá trị)
            if (!string.IsNullOrWhiteSpace(request.Phone))
            {
                user.Phone = request.Phone;
            }
            else
            {
                // Tùy theo logic nghiệp vụ, nếu request.Phone rỗng, bạn có thể gán null hoặc giữ giá trị cũ.
                // Giả sử logic là cho phép xóa số điện thoại nếu gửi lên rỗng
                user.Phone = null;
            }

            // --- 4. LƯU THAY ĐỔI VÀO DATABASE ---
            // Entity Framework Core sẽ tự động phát hiện các thay đổi (user.Username, user.Phone) 
            // và tạo câu lệnh UPDATE khi gọi SaveChangesAsync()
            await _context.SaveChangesAsync();

            // --- 5. Prepare Response (Lấy giá trị ĐÃ CẬP NHẬT từ đối tượng 'user') ---
            UpdateUserInforResponse updateUserInforResponse = new UpdateUserInforResponse();
            updateUserInforResponse.Id = user.Id;
            updateUserInforResponse.Username = user.Username; // Lấy từ user (giá trị mới)
            updateUserInforResponse.Email = user.Email;

            // phone
            if (!string.IsNullOrWhiteSpace(user.Phone))
            {
                updateUserInforResponse.Phone = user.Phone; // Lấy từ user (giá trị mới)
            }
            else
            {
                updateUserInforResponse.Phone = "";
            }

            // roles
            var roles = await GetUserRoles(user.Id);
            updateUserInforResponse.Roles = roles;

            return updateUserInforResponse;
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

        public async Task<string> CheckSendMail(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            // 2. Tạo và lưu OTP
            // Giả định _otpService.GenerateAndStoreOtpAsync trả về string OTP
            var otpCode = await _otpService.GenerateAndStoreOtpAsync(user.Id, OtpType.ResetPassword);

            // **BỎ QUA:** Không gửi email nữa, nên loại bỏ dòng này
            await _emailService.SendPasswordResetEmail(user.Email, otpCode);
            return "Send Mail OK";
        }
    }
}
