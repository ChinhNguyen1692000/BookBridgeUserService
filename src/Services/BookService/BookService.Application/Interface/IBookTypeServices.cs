using BookService.Application.Models;
using BookService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Application.Interface
{
    public interface IBookTypeServices
    {
        Task<BookType> CreateAsync(BookTypeCreateRequest request);
        Task<BookType> UpdateAsync(BookTypeUpdateRequest request);
        Task<bool> Remove(int id);
        Task<bool> Active(int id);
        Task<List<BookType>> GetAllAsync();
        Task<BookType?> GetByIdAsync(int id);
        Task<List<BookType>> GetActiveType();
        Task<List<BookType>> GetUnactiveType();
    }
}
