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
            optionsBuilder.UseNpgsql("User Id=postgres.hhmcmpnmytivfgsvbwpo;Password=0328802216Zz.;Server=aws-1-us-east-2.pooler.supabase.com;Port=5432;Database=postgres");

            return new UserDbContext(optionsBuilder.Options);
        }
    }
}
