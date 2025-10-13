using Microsoft.EntityFrameworkCore;
using UserService.Domain.Entities;
using UserService.Domain.Events;

namespace UserService.Infrastructure.Data
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<UserOtp> UserOtps { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
        public DbSet<UserCreatedEvent> UserCreatedEvents { get; set; } // Optional
        public DbSet<RefreshToken> RefreshTokens { get; set; } // Thêm DbSet cho RefreshToken

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // User
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(u => u.Id);
                entity.Property(u => u.Username).IsRequired().HasMaxLength(100);
                entity.Property(u => u.Email).IsRequired().HasMaxLength(200);
                entity.Property(u => u.PasswordHash).HasMaxLength(200);
                entity.Property(u => u.Phone).HasMaxLength(20);
                entity.Property(u => u.CreatedAt).IsRequired();
            });

            // Role
            modelBuilder.Entity<Role>(entity =>
            {
                entity.HasKey(r => r.Id);
                entity.Property(r => r.RoleName).IsRequired().HasMaxLength(50); // Thêm dòng này
                entity.HasMany(r => r.UserRoles)
                      .WithOne(ur => ur.Role)
                      .HasForeignKey(ur => ur.RoleId);
            });

            // UserRole (many-to-many)
            modelBuilder.Entity<UserRole>(entity =>
            {
                entity.HasKey(ur => new { ur.UserId, ur.RoleId });

                entity.HasOne(ur => ur.User)
                      .WithMany(u => u.UserRoles)
                      .HasForeignKey(ur => ur.UserId);

                entity.HasOne(ur => ur.Role)
                      .WithMany(r => r.UserRoles)
                      .HasForeignKey(ur => ur.RoleId);
            });

            // UserOtp
            modelBuilder.Entity<UserOtp>(entity =>
            {
                entity.HasKey(o => o.Id);
                entity.Property(o => o.UserId).IsRequired();
                entity.Property(o => o.OtpCode).IsRequired().HasMaxLength(10);
                entity.Property(o => o.Expiry).IsRequired();
                entity.Property(o => o.Type).IsRequired();
                entity.Property(o => o.IsUsed).IsRequired().HasDefaultValue(false);
                entity.HasOne(u => u.User)
                     .WithMany(u => u.UserOtps)
                     .HasForeignKey(o => o.UserId)
                     .OnDelete(DeleteBehavior.Cascade);  
            });

            // PasswordResetToken
            modelBuilder.Entity<PasswordResetToken>(entity =>
            {
                entity.HasKey(t => t.Id);
                entity.Property(t => t.Token).IsRequired().HasMaxLength(255);
                entity.Property(t => t.ExpiryDate).IsRequired();
                entity.HasIndex(t => t.Token).IsUnique();

                entity.HasOne<User>()
                      .WithMany()
                      .HasForeignKey(t => t.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            // Optional: UserCreatedEvent
            modelBuilder.Entity<UserCreatedEvent>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Timestamp).IsRequired();
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.Email).IsRequired().HasMaxLength(200);
            });

            // RefreshToken
            modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(rt => rt.Id);
                entity.Property(rt => rt.Token).IsRequired().HasMaxLength(255);
                entity.Property(rt => rt.Expiry).IsRequired();
                entity.Property(rt => rt.IsRevoked).IsRequired().HasDefaultValue(false);

                entity.HasOne(rt => rt.User)
                      .WithMany(u => u.RefreshTokens)
                      .HasForeignKey(rt => rt.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<Role>().HasData(
                new Role { Id = Guid.Parse("11111111-1111-1111-1111-111111111111"), RoleName = "User" },
                new Role { Id = Guid.Parse("22222222-2222-2222-2222-222222222222"), RoleName = "Admin" },
                new Role { Id = Guid.Parse("33333333-3333-3333-3333-333333333333"), RoleName = "Bookstore_owner" }
            );
        }
    }
}
