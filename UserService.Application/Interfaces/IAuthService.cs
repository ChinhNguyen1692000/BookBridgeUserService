using UserService.Application.Interfaces;
using UserService.Application.Models;
using System.Threading.Tasks;

namespace UserService.Application.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponse> Register(RegisterRequest request);
        // Email login
        Task<AuthResponse> Login(LoginRequest request);
        Task ForgetPassword(string email);
        Task ResetPassword(string token, string newPassword);

        // Google Login
        Task<AuthResponse> GoogleLogin(GoogleLoginRequest request);
    }
}