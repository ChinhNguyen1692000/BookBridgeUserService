using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Application.Models
{
    public class BookImageDTO
    {
        public int Id { get; set; }
        public int BookId { get; set; }

        public string ImageUrl { get; set; }

        public DateTime UploadedAt { get; set; } 
    }
    public class BookImageCreateRequest
    {
        public int BookId { get; set; }

        public string ImageUrl { get; set; }
    }
    public class BookImageUpdateRequest
    {
        public int Id { get; set; }
        public int BookId { get; set; }

        public string ImageUrl { get; set; }

    }
}
