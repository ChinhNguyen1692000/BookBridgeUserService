using Microsoft.AspNetCore.Mvc;
using UserService.Application.Interfaces;
using UserService.Application.Models;
using System.Threading.Tasks;
using System;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using UserService.Application.CustomExceptions;
using System.IdentityModel.Tokens.Jwt;

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


        // GET: api/Auth
        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> GetAllUser([FromQuery] int pageNo, [FromQuery] int pageSize)
        {
            var list = await _authService.GetAllAsync(pageNo, pageSize);
            return Ok(list);
        }


        // GET: api/Auth/{id}
        [Authorize(Roles = "Admin")]
        [HttpGet("{id}")]
        public async Task<IActionResult> GetUserById(Guid id)
        {
            var user = await _authService.GetByIdAsync(id);
            if (user == null) return NotFound();
            return Ok(user);
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

        // POST: api/Auth/active-email
        [HttpPost("active-email")]
        public async Task<IActionResult> ActiveEmailAccount([FromBody] OtpRequest otp)
        {
            var (success, message) = await _authService.ActiveEmailAccount(otp.OtpCode, otp.Email);
            if (!success)
                return BadRequest(new { message });
            return Ok(new { message });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var response = await _authService.Login(request);
                return Ok(response);
            }
            catch (AccountNotActiveException ex)
            {
                // Có thể trả 403 Forbidden hoặc 200 OK với cờ frontend
                return BadRequest(new { message = ex.Message });
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception)
            {
                return StatusCode(500, new { message = "Something went wrong." });
            }
        }


        // PUT: api/Auth/update-user-info
        [Authorize]
        [HttpPut("update-user-info")]
        public async Task<IActionResult> UpdateUserNameAndPhoneNumber([FromBody] UpdateUserRequest request)
        {


            // Lấy userId từ token
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new { message = "User is not authenticated." });
            }

            try
            {
                var message = await _authService.UpdateUserNameAndPhoneNumberAsync(request, userId);
                return Ok(new { message });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }

        // PUT: api/Auth/update-user-password
        [Authorize]
        [HttpPut("update-user-password")]
        public async Task<IActionResult> UpdateUserPassword([FromBody] UpdateUserPasswordRequest request)
        {

            // Lấy userId từ token
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new { message = "User is not authenticated." });
            }

            try
            {
                var message = await _authService.UpdateUserPasswordAsync(request, userId);
                return Ok(new { message });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }

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
            if (string.IsNullOrEmpty(request.Otp) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { message = "Token and New Password are required." });
            }

            try
            {
                // Giả định bạn đã chỉnh sửa LoginRequest để chấp nhận Token và NewPassword
                await _authService.ResetPassword(request.Email, request.Otp, request.Password, request.Repassword);
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
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { message = "Google Login failed: " + ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Internal server error: " + ex.Message });
            }
        }

        // POST: api/Auth/refresh-token
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                // // Thêm kiểm tra Header
                // if (!Request.Headers.ContainsKey("Authorization") ||
                //     !Request.Headers["Authorization"].ToString().StartsWith("Bearer "))
                // {
                //     // Trả về 400 nếu Access Token cũ không được gửi lên
                //     return BadRequest(new { message = "Access Token (Authorization header) is required for refreshing." });
                // }

                var oldAccessToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                var authResponse = await _authService.RefreshTokenAsync(request, oldAccessToken);
                return Ok(authResponse);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { message = "Refresh token is invalid or expired. Please login again." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Internal server error: " + ex.Message });
            }
        }

        // POST: api/Auth/logout
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {

            // Lấy userId từ token
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // Lấy jti từ token
            var jtiClaim = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value; // Cần dùng System.IdentityModel.Tokens.Jwt;

            // Nếu không tìm thấy userId trong token, trả về lỗi
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                return Unauthorized(new { message = "User is not authenticated." });

            // Kiểm tra nếu jti hoặc userId bị thiếu
            if (string.IsNullOrEmpty(jtiClaim)) // Kiểm tra JTI có tồn tại không
            {
                return BadRequest(new { message = "JTI claim is missing from access token." });
            }

            try
            {
                await _authService.LogoutAsync(userId, jtiClaim);
                return Ok(new { message = "Logout successful." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Internal server error: " + ex.Message });
            }
        }
    }
}