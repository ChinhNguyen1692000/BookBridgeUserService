using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BookstoreService.Domain.Entities
{
	[Table("Messages")]
	public class Message
	{
		[Key]
		[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
		public long Id { get; set; }

		[Required]
		[MaxLength(100)]
		public string EventType { get; set; }  // Tên event, ví dụ "BookstoreCreatedEvent"

		[Required]
		public string Payload { get; set; }  // Dữ liệu JSON của message

		[MaxLength(50)]
		public string Status { get; set; } = "Pending";  // Pending, Published, Failed,...

		[MaxLength(255)]
		public string TraceId { get; set; }  // Dùng để trace flow giữa các service

		public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

		public DateTime? PublishedAt { get; set; }  // Khi message được publish

		public int RetryCount { get; set; } = 0;  // Số lần retry publish nếu fail
	}
}
