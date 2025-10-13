using BookService.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BookService.Infracstructure.DBContext
{
    public class BookDBContext : DbContext
    {
        public BookDBContext(DbContextOptions<BookDBContext> options)
            : base(options)
        {
        }

        // DbSets
        public DbSet<Book> Books { get; set; }
        public DbSet<BookImage> BookImages { get; set; }
        public DbSet<BookType> BookTypes { get; set; }
        public DbSet<Message> Messages { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // 📘 Book
            modelBuilder.Entity<Book>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.Property(e => e.Title)
                      .IsRequired()
                      .HasMaxLength(255);

                entity.Property(e => e.ISBN)
                      .IsRequired()
                      .HasMaxLength(20);

                entity.Property(e => e.ImageUrl)
                      .IsRequired()
                      .HasMaxLength(500);

                entity.Property(e => e.CreatedAt)
                      .HasColumnType("timestamp")
                      .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(e => e.UpdatedAt)
                      .HasColumnType("timestamp")
                      .IsRequired(false);

                entity.Property(e => e.IsActive)
                      .HasDefaultValue(true);

                // 💰 Giá sách
                entity.Property(e => e.Price)
                      .HasColumnType("numeric(18,2)") // PostgreSQL equivalent of decimal(18,2)
                      .IsRequired();

                // Book → BookType (many-to-one)
                entity.HasOne(b => b.BookType)
                      .WithMany()
                      .HasForeignKey(b => b.TypeId)
                      .OnDelete(DeleteBehavior.Restrict);

                // Book → BookImages (one-to-many)
                entity.HasMany(b => b.BookImages)
                      .WithOne(bi => bi.Book)
                      .HasForeignKey(bi => bi.BookId)
                      .OnDelete(DeleteBehavior.Cascade);
            });


            // 🖼️ BookImage
            modelBuilder.Entity<BookImage>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.Property(e => e.ImageUrl)
                      .IsRequired()
                      .HasMaxLength(500);

                entity.Property(e => e.UploadedAt)
                      .HasColumnType("timestamp")
                      .HasDefaultValueSql("CURRENT_TIMESTAMP");
            });

            // 🏷️ BookType
            modelBuilder.Entity<BookType>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.Property(e => e.Name)
                      .IsRequired()
                      .HasMaxLength(100);

                entity.Property(e => e.Description)
                      .HasMaxLength(255);

                entity.Property(e => e.isActive)
                      .HasDefaultValue(true); // thêm cột isActive
            });

            // 📩 Message
            modelBuilder.Entity<Message>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.Property(e => e.EventType)
                      .IsRequired()
                      .HasMaxLength(100);

                entity.Property(e => e.Status)
                      .HasMaxLength(50)
                      .HasDefaultValue("Pending");

                entity.Property(e => e.CreatedAt)
                      .HasColumnType("timestamp")
                      .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(e => e.PublishedAt)
                      .HasColumnType("timestamp")
                      .IsRequired(false);

                entity.Property(e => e.TraceId)
                      .HasMaxLength(255);
            });
        }
    }
}
