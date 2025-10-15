// Tệp: DTOs/CheckEmailRequest.cs

using System.ComponentModel.DataAnnotations;

public class CheckEmailRequest
{
    // THAY ĐỔI: Thêm thuộc tính validation
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")] 
    public string Email { get; set; }
}

// Tệp: DTOs/RegisterRequest.cs

public class RegisterRequest
{
    [Required]
    public string Username { get; set; }

    // THAY ĐỔI: Thêm thuộc tính validation
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    public string Email { get; set; }
    
    // Giả sử có thêm Phone
    public string Phone { get; set; }

    [Required]
    public string Password { get; set; }

    [Required]
    public string Repassword { get; set; }

    [Required]
    public string OtpCode { get; set; } 
}