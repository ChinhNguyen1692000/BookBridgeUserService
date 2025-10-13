using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookstoreService.Application.Models
{
    public class BookstoreDTO
    {
    }
    public class BookstoreCreateRequest
    {
        public string Name { get; set; }
        public string OwnerId { get; set; }

        [MaxLength(255)]
        public string Address { get; set; }

        [MaxLength(500)]
        public string ImageUrl { get; set; }

        [MaxLength(15)]
        public string PhoneNumber { get; set; }
    }
    public class BookstoreUpdateRequest
    {
        public int Id { get; set; }
        public string Name { get; set; }

        [MaxLength(255)]
        public string Address { get; set; }

        [MaxLength(500)]
        public string ImageUrl { get; set; }

        [MaxLength(15)]
        public string PhoneNumber { get; set; }
    }


}
