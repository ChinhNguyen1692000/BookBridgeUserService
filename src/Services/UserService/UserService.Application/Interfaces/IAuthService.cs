using UserService.Application.Interfaces;
using UserService.Application.Models;
using System.Threading.Tasks;
using Common.Paging;
using UserService.Domain.Entities;

namespace UserService.Application.Interfaces
{
    public interface IAuthService
    {
        Task<RegisterResponse> Register(RegisterRequest request);
        // Email login
        Task<AuthResponse> Login(LoginRequest request);
        Task ForgetPassword(string email);
        // 
        Task ResetPassword(string email, string otp, string newPassword, string confirmPassword);

        // Google Login
        Task<AuthResponse> GoogleLogin(GoogleLoginRequest request);

        // Kích hoạt tài khoản qua email
        Task<(bool Success, string Message)> ActiveEmailAccount(string otp, string email);

        // Lấy thông tin người dùng bằng ID
        Task<User> GetByIdAsync(Guid userId);

        // Lấy tất cả người dùng với phân trang
        Task<PagedResult<User>> GetAllAsync(int pageNo, int pageSize);
        
        // Cập nhật username và phone number
        Task<string> UpdateUserNameAndPhoneNumberAsync(UpdateUserRequest request, Guid userId);

        // Cập nhật mật khẩu người dùng
        Task<string> UpdateUserPasswordAsync(UpdateUserPasswordRequest request, Guid userId);

        // Đăng xuất (revoke) refresh token
        Task LogoutAsync(Guid userId,string jtiClaim);

        // Tạo mới access token từ refresh token
        Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request, string oldAccessToken);

    }
}