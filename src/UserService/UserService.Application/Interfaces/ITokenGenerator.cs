using UserService.Domain.Entities;
using UserService.Application.Models;

namespace UserService.Application.Interfaces
{
    public interface ITokenGenerator
    {
        Task<AuthResponse> GenerateToken(User user, List<string> roleNames);
    }
}