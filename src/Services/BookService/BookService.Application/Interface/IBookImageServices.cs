using BookService.Application.Models;
using BookService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Application.Interface
{
    public interface IBookImageServices
    {
        Task<BookImage> CreateAsync(BookImageCreateRequest request);
        Task<BookImage> UpdateAsync(BookImageUpdateRequest request);

        Task<bool> DeleteAsync(int id);

        Task<IEnumerable<BookImage>> GetAllAsync();
        Task<BookImage> GetByBookIdAsync(int bookId);
    }
}
