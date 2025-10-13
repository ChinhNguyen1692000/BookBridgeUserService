using BookService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Application.Models
{
    public class BookDTO
    {
        public int Id { get; set; }
        public string ISBN { get; set; }
        public int BookstoreId { get; set; }
        public string Title { get; set; }
        public string Author { get; set; }
        public string? Translator { get; set; }
        public string Publisher { get; set; }
        public DateTime? PublishedDate { get; set; }
        public string Language { get; set; }
        public string Description { get; set; }
        public decimal Price { get; set; }
        public int? PageCount { get; set; }
        public int TypeId { get; set; }
        public string ImageUrl { get; set; }
        public double? AverageRating { get; set; }
        public int? RatingsCount { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public bool IsActive { get; set; } = true;
    }
    public class BookCreateRequest
    {
        public string ISBN { get; set; }
        public int BookstoreId { get; set; }
        public string Title { get; set; }
        public string Author { get; set; }
        public string? Translator { get; set; }
        public string Publisher { get; set; }
        public DateTime? PublishedDate { get; set; }
        public decimal Price { get; set; }
        public string Language { get; set; }
        public string Description { get; set; }
        public int? PageCount { get; set; }
        public int TypeId { get; set; }
        public string ImageUrl { get; set; }
    }
    public class BookUpdateReuest
    {
        public int Id { get; set; }
        public string ISBN { get; set; }
        public int BookstoreId { get; set; }
        public string Title { get; set; }
        public string Author { get; set; }
        public string? Translator { get; set; }
        public decimal Price { get; set; }
        public string Publisher { get; set; }
        public DateTime? PublishedDate { get; set; }
        public string Language { get; set; }
        public string Description { get; set; }
        public int? PageCount { get; set; }
        public int TypeId { get; set; }
        public string ImageUrl { get; set; }
    }
}
