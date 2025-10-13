using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BookstoreService.Domain.Entities
{
	[Table("Bookstores")]
	public class Bookstore
	{
		[Key]
		[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
		public int Id { get; set; }

		[Required]
		[MaxLength(100)]
		public string Name { get; set; }

		[MaxLength(255)]
		public string Address { get; set; }

		[MaxLength(100)]
		public string OwnerId { get; set; }

		[MaxLength(15)]
		public string PhoneNumber { get; set; }

        [MaxLength(500)]
        public string ImageUrl { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
		public DateTime? UpdatedAt { get; set; }

		public bool IsActive { get; set; } = true;
	}
}
