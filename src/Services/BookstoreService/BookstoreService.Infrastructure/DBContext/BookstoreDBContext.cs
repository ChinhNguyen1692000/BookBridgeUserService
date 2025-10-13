using BookstoreService.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BookstoreService.Infrastructure.DBContext
{
    public class BookstoreDBContext : DbContext
    {
        public BookstoreDBContext(DbContextOptions<BookstoreDBContext> options)
            : base(options)
        {
        }

        public DbSet<Bookstore> Bookstores { get; set; }
        public DbSet<Message> Messages { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // 📌 Bookstore
            modelBuilder.Entity<Bookstore>(entity =>
            {
                entity.HasKey(b => b.Id);

                entity.Property(b => b.Name)
                      .IsRequired()
                      .HasMaxLength(100);

                entity.Property(b => b.Address)
                      .IsRequired()
                      .HasMaxLength(255);

                entity.Property(b => b.OwnerId)
                      .IsRequired()
                      .HasMaxLength(100);

                entity.Property(b => b.PhoneNumber)
                      .IsRequired()
                      .HasMaxLength(15);

                entity.Property(b => b.ImageUrl)
                      .IsRequired()
                      .HasMaxLength(500)
                      .HasDefaultValue("default-image.png");

                // ✅ CreatedDate và UpdatedAt đều timestamp (không time zone)
                entity.Property(b => b.CreatedDate)
                      .HasColumnType("timestamp")
                      .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(b => b.UpdatedAt)
                      .HasColumnType("timestamp")
                      .IsRequired(false); // nullable

                entity.Property(b => b.IsActive)
                      .HasDefaultValue(true);
            });

            // 📌 Message
            modelBuilder.Entity<Message>(entity =>
            {
                entity.HasKey(m => m.Id);

                entity.Property(m => m.EventType)
                      .IsRequired()
                      .HasMaxLength(100);

                entity.Property(m => m.Payload)
                      .IsRequired();

                entity.Property(m => m.Status)
                      .HasMaxLength(50)
                      .HasDefaultValue("Pending");

                entity.Property(m => m.TraceId)
                      .HasMaxLength(255);

                entity.Property(m => m.CreatedAt)
                      .HasColumnType("timestamp")
                      .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(m => m.PublishedAt)
                      .HasColumnType("timestamp")
                      .IsRequired(false);

                entity.Property(m => m.RetryCount)
                      .HasDefaultValue(0);
            });
        }
    }
}
