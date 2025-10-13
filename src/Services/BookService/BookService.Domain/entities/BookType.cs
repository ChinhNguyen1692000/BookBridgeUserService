using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BookService.Domain.Entities
{
    [Table("BookTypes")]
    public class BookType
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } 

        [MaxLength(255)]
        public string? Description { get; set; }
        public bool isActive { get; set; }
    }
}
