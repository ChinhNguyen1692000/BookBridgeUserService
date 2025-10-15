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

        [HttpGet("/api/healthz")] // <-- Change: Explicitly set the absolute path
        public IActionResult HealthCheck() => Ok("Healthy");

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

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            // Kiểm tra ràng buộc 1: Người dùng KHÔNG được tự xóa tài khoản của chính mình (nếu dùng chung endpoint)
            // Lấy userId từ token của người đang yêu cầu
            var currentUserIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!string.IsNullOrEmpty(currentUserIdClaim) && Guid.TryParse(currentUserIdClaim, out var currentUserId) && currentUserId == id)
            {
                // Trả về 403 Forbidden hoặc 400 BadRequest để cấm người dùng tự xóa mình
                return StatusCode(403, new { message = "Admin không được tự xóa tài khoản của chính mình thông qua API này." });

            }

            try
            {
                // Xử lý logic xóa (bao gồm cả ràng buộc, kiểm tra quyền và NotFound) sẽ nằm trong service.
                var message = await _authService.DeleteUserAsync(id);

                // Nếu service trả về thành công
                return Ok(new { message = message ?? $"Người dùng với ID '{id}' đã được xóa thành công." });
            }
            catch (Application.CustomExceptions.NotFoundException ex)
            {
                // Bắt lỗi khi không tìm thấy người dùng
                return NotFound(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                // Bắt lỗi về ràng buộc: Ví dụ: "Không thể xóa người dùng vì có đơn hàng/bài đăng liên quan."
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                // Bắt lỗi server chung (500)
                return StatusCode(500, new { message = "Lỗi hệ thống khi xóa người dùng: " + ex.Message });
            }
        }

        // POST: api/Auth/register
        // Bước 2: Đăng ký đầy đủ, kèm OTP. Kiểm tra OTP, lưu user, kích hoạt tài khoản, vô hiệu hóa OTP.
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            try
            {
                var response = await _authService.Register(request);
                return Ok(new { message = "Register success. Your account has been active. Please login", response });
            }
            catch (Exception ex)
            {
                // Nên sử dụng Custom Exception và HttpStatus code phù hợp hơn
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize(Roles = "Buyer")]
        [HttpPost("active-seller")]
        public async Task<IActionResult> ActiveSellerAccount()
        {
            // Lấy userId từ token
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new { message = "User is not authenticated." });
            }

            try
            {
                var (success, message) = await _authService.ActiveSellerAccount(userId);
                if (!success)
                    return BadRequest(new { message });

                return Ok(new { message });
            }
            catch (Exception ex)
            {
                // Nếu muốn log, inject ILogger<AuthController> và gọi logger ở constructor
                return StatusCode(500, new { message = "Internal server error: " + ex.Message });
            }
        }

        // POST: api/Auth/check-email
        // Bước 1: Nhận email, kiểm tra cú pháp (bởi [EmailAddress]), kiểm tra trùng lặp DB, tạo OTP
        [HttpPost("check-email")]
        public async Task<IActionResult> CheckEmailForRegistration([FromBody] CheckEmailRequest request)
        {
            // 🚨 KHÔNG CẦN Thêm ModelState.IsValid nếu dùng [ApiController]
            // Vì [ApiController] tự động kiểm tra cú pháp và trả về 400 nếu Validation thất bại.

            try
            {
                var response = await _authService.CheckEmailForRegistration(request.Email);
                return Ok(new { message = "OTP generated successfully. Please check the server log for the code.", response });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
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
        public async Task<IActionResult> ForgetPassword([FromQuery] string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                return BadRequest(new { message = "Email không được để trống." });
            }

            try
            {
                // 1. Gọi Service và nhận về OTP
                var otp = await _authService.ForgetPassword(email); // Gọi phương thức đã chỉnh sửa

                // 2. Trả về thông báo thành công và OTP cho frontend
                // Frontend sẽ dùng message để biết thành công và dùng OTP để hiển thị hoặc log (nếu cần thiết cho việc debug)
                return Ok(new
                {
                    message = "Email đã được đăng ký. Chuyển sang màn hình nhập OTP và mật khẩu mới.",
                    otpCode = otp,
                    success = true // Thêm field success để frontend dễ kiểm tra
                });
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("chưa được đăng ký"))
            {
                // 3. Bắt lỗi khi email chưa đăng ký
                return NotFound(new
                {
                    message = ex.Message, // "Email chưa được đăng ký trong hệ thống."
                    success = false
                });
            }
            catch (Exception ex)
            {
                // 4. Bắt các lỗi khác (lỗi server, lỗi tạo OTP...)
                return StatusCode(500, new
                {
                    message = "Đã xảy ra lỗi hệ thống khi tạo OTP. Vui lòng thử lại sau.",
                    details = ex.Message,
                    success = false
                });
            }
        }

        // POST: api/Auth/reset-password
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetRequest request)
        {
            // ... (Code kiểm tra input và gọi service ResetPassword không đổi) ...
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Otp) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { message = "Email, OTP và Mật khẩu mới không được để trống." });
            }

            try
            {
                await _authService.ResetPassword(request.Email, request.Otp, request.Password, request.Repassword);
                return Ok(new { message = "Mật khẩu đã được đặt lại thành công." });
            }
            catch (Exception ex)
            {
                // Bắt lỗi như OTP không hợp lệ, email không tồn tại, mật khẩu không khớp, ...
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