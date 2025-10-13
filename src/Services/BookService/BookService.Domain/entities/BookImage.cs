using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace BookService.Domain.Entities
{
    [Table("BookImages")]
    public class BookImage
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        public int BookId { get; set; } 

        [Required]
        [MaxLength(500)]
        public string ImageUrl { get; set; }

        public DateTime UploadedAt { get; set; } = DateTime.UtcNow;

        // Navigation
        [ForeignKey("BookId")]
        [JsonIgnore]
        public Book Book { get; set; }
    }
}
