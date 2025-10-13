using BookService.Application.Models;
using BookService.Domain.Entities;
using Common.Paging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Application.Interface
{
    public interface IBookServices
    {
        Task<PagedResult<Book>> Search(string? searchValue, int pageNo = 1, int pageSize = 10);
        Task<PagedResult<Book>> Filter(int? typeId, decimal? price, int pageNo = 1, int pageSize = 10);
        Task<PagedResult<Book>> GetAllAsync(int pageNo, int pageSize);

        Task<Book> GetByIdAsync(int id);

        Task<Book> CreateAsync(BookCreateRequest request);
        Task<Book> UpdateAsync(BookUpdateReuest request);

        Task<bool> Remove(int id);
        Task<bool> Active(int id);

        Task<PagedResult<Book>> GetActiveByBookstoreAsync(int bookstoreId, int pageNo, int pageSize);

        Task<PagedResult<Book>> GetInactiveByBookstoreAsync(int bookstoreId, int pageNo, int pageSize);
    }
}
