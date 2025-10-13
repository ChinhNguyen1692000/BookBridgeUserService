using UserService.Domain.Entities;

public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string Token { get; set; } = null!;
    public DateTime Expiry { get; set; }
    public bool IsRevoked { get; set; } = false;
    public User User { get; set; } = null!;
}
