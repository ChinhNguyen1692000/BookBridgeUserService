using OrderService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OrderService.Application.Models
{
    public class OrderDTO
    {
        public int Id { get; set; }
        public string OrderNumber { get; set; }
        public string CustomerId { get; set; }
        public DateTime OrderDate { get; set; } 
        public decimal TotalAmount { get; set; }
        public string ShippingAddress { get; set; }
        public DateTime? ShippedDate { get; set; }
        public string Status { get; set; }
        public ICollection<OrderItem> OrderItems { get; set; } = new List<OrderItem>();
    }
    public class OrderCreateRequest
    {
        public string CustomerId { get; set; }
        public decimal TotalAmount { get; set; }
        public string ShippingAddress { get; set; }
        public ICollection<OrderItemCreateRequest> OrderItems { get; set; } = new List<OrderItemCreateRequest>();

    }

}
