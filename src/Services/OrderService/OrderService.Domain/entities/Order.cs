    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    namespace OrderService.Domain.Entities
    {
        [Table("Orders")]
        public class Order
        {
            [Key]
            [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
            public int Id { get; set; }

            [Required]
            [MaxLength(50)]
            public string OrderNumber { get; set; }

            [Required]
            public string CustomerId { get; set; }    

            [Required]
            public DateTime OrderDate { get; set; } = DateTime.UtcNow;

            [Required]
            [Column(TypeName = "decimal(18,2)")]
            public decimal TotalAmount { get; set; }
            [MaxLength(255)]
            public string ShippingAddress { get; set; }
            public DateTime? ShippedDate { get; set; }

            [MaxLength(50)]
            public string Status { get; set; } = "Pending"; 

            // Navigation property
            public ICollection<OrderItem> OrderItems { get; set; } = new List<OrderItem>();
        }
    }
