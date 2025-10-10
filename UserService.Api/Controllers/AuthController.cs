using Microsoft.AspNetCore.Mvc;
using UserService.Application.Interfaces;
using UserService.Application.Models;
using System.Threading.Tasks;
using System;

namespace UserService.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // POST: api/Auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            try
            {
                var response = await _authService.Register(request);
                return Ok(response);
            }
            catch (Exception ex)
            {
                // Nên sử dụng Custom Exception và HttpStatus code phù hợp hơn
                return BadRequest(new { message = ex.Message });
            }
        }

        // POST: api/Auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var response = await _authService.Login(request);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Unauthorized(new { message = "Email or password is incorrect." });
            }
        }
        
        // **TODO: Thêm ForgetPassword (Saga Pattern)**
        // **TODO: Thêm Google Login**



        // POST: api/Auth/forget-password
        [HttpPost("forget-password")]
        public async Task<IActionResult> ForgetPassword([FromQuery] string email) // Dùng FromQuery hoặc dùng 1 Model đơn giản
        {
            try
            {
                await _authService.ForgetPassword(email);
                // Luôn trả về 200/202 để tránh bị brute-force check email
                return Accepted(new { message = "If the email exists, a password reset link has been sent." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = ex.Message });
            }
        }

        // POST: api/Auth/reset-password
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetRequest request) // Tận dụng LoginRequest để truyền Token và NewPassword
        {
            // **LƯU Ý:** Đảm bảo LoginRequest có 2 field Token và Password/Repassword
            if (string.IsNullOrEmpty(request.Token) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { message = "Token and New Password are required." });
            }

            try
            {
                // Giả định bạn đã chỉnh sửa LoginRequest để chấp nhận Token và NewPassword
                await _authService.ResetPassword(request.Token, request.Password);
                return Ok(new { message = "Password has been reset successfully." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
        
                // POST: api/Auth/google-login
        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request)
        {
            try
            {
                var response = await _authService.GoogleLogin(request);
                return Ok(response);
            }
            catch (NotImplementedException)
            {
                return StatusCode(501, new { message = "Google Login is not fully implemented yet." });
            }
            catch (Exception ex)
            {
                return Unauthorized(new { message = "Google Login failed: " + ex.Message });
            }
        }
    }
}