namespace UserService.Application.Models
{
    public class GoogleLoginRequest
    {
        public string IdToken { get; set; } // Token được gửi từ client Google Sign-In
    }
}