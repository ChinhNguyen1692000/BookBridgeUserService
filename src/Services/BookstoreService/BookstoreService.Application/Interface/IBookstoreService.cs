using BookstoreService.Application.Models;
using BookstoreService.Domain.Entities;
using Common.Paging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookstoreService.Application.Interface
{
    public interface IBookstoreService
    {
        Task<Bookstore> CreateAsync(BookstoreCreateRequest request);
        Task<bool> Ban(int id);
        Task<Bookstore> UpdateAsync(BookstoreUpdateRequest request);
        Task<Bookstore> GetByIdAsync(int id);
        Task<PagedResult<Bookstore>> GetAllAsync(int pageNo, int pageSize);
    }
}
