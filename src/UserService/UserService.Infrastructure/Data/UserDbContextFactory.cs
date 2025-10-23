using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace UserService.Infrastructure.Data
{
    public class UserDbContextFactory : IDesignTimeDbContextFactory<UserDbContext>
    {
        public UserDbContext CreateDbContext(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<UserDbContext>();
            var connectionString = configuration.GetConnectionString("BookServiceConnection"); // đổi theo tên connection string
            optionsBuilder.UseNpgsql(connectionString); // dùng PostgreSQL

            return new UserDbContext(optionsBuilder.Options);
        }
    }
}
