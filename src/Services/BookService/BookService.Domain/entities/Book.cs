using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BookService.Domain.Entities
{
    [Table("Books")]
    public class Book
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        [MaxLength(20)]
        public string ISBN { get; set; }

        [Required]
        public int BookstoreId { get; set; }

        [Required]
        [MaxLength(255)]
        public string Title { get; set; }

        [MaxLength(255)]
        public string Author { get; set; }

        [MaxLength(255)]
        public string? Translator { get; set; }

        [MaxLength(255)]
        public string Publisher { get; set; }

        public DateTime? PublishedDate { get; set; }

        [MaxLength(50)]
        public string Language { get; set; }

        [MaxLength(4000)]
        public string Description { get; set; }

        public int? PageCount { get; set; }

        // ---- Relationship to BookType ----
        [Required]
        [ForeignKey(nameof(BookType))]
        public int TypeId { get; set; }
        
        public BookType BookType { get; set; }

        [Required]
        [MaxLength(500)]
        public string ImageUrl { get; set; }

        [Column(TypeName = "numeric(18,2)")]
        public decimal Price { get; set; }
        public double? AverageRating { get; set; }
        public int? RatingsCount { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public bool IsActive { get; set; } = true;

        // Navigation
        public ICollection<BookImage> BookImages { get; set; } = new List<BookImage>();
    }
}
