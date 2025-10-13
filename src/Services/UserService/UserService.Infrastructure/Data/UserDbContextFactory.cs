using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace UserService.Infrastructure.Data
{
    public class UserDbContextFactory : IDesignTimeDbContextFactory<UserDbContext>
    {
        public UserDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<UserDbContext>();

            // ⚠️ Dùng cấu hình PostgreSQL đúng của bạn — KHÔNG lấy từ Docker vì EF chạy ngoài container
            optionsBuilder.UseNpgsql("Host=localhost;Port=5432;Database=postgres;Username=postgres;Password=12345;");

            return new UserDbContext(optionsBuilder.Options);
        }
    }
}
