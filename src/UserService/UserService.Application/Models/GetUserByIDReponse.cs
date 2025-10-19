public class GetUserByIdResponse
{
    public Guid Id { get; set; }
    public string Username { get; set; }
    public string? Phone { get; set; }
    public string Email { get; set; }
    public string? PasswordHash { get; set; }
    public DateTime CreatedAt { get; set; }

    // Danh sách role
    public List<UserRoleDto> Roles { get; set; } = new List<UserRoleDto>();

    public bool IsGoogleUser { get; set; } = false;
    public bool IsActive { get; set; } = false;

    public ICollection<UserOtp> UserOtps { get; set; } = new List<UserOtp>();
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

// DTO riêng cho Role
public class UserRoleDto
{
    public Guid RoleId { get; set; }
    public string RoleName { get; set; }
}
