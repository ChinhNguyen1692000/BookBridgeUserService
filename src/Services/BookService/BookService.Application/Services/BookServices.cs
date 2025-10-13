using AutoMapper;
using Azure;
using BookService.Application.Interface;
using BookService.Application.Models;
using BookService.Domain.Entities;
using BookService.Infracstructure.Repositories;
using Common.Paging;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BookService.Application.Services
{
    public class BookServices : IBookServices
    {
        private readonly BookRepository _repo;
        private readonly IMapper _mapper;

        public BookServices(BookRepository repo, IMapper mapper)
        {
            _repo = repo;
            _mapper = mapper;
        }
        public async Task<PagedResult<Book>> Search(string? searchValue, int pageNo = 1, int pageSize = 10)
        {
            var bL = await _repo.SearchByTitleOrAuthor(searchValue);
            var bLPaging = PagedResult<Book>.Create(bL, pageNo, pageSize);
            return bLPaging;
        }
        public async Task<PagedResult<Book>> Filter(int? typeId, decimal? price, int pageNo = 1, int pageSize = 10)
        {
            var bL = await _repo.Filter(typeId, price);
            var bLPaging = PagedResult<Book>.Create(bL, pageNo, pageSize);
            return bLPaging;
        }
        public async Task<PagedResult<Book>> GetAllAsync(int pageNo, int pageSize)
        {
            var bL = await _repo.GetAllAsync();
            var bLPaging = PagedResult<Book>.Create(bL, pageNo, pageSize);
            return bLPaging;
        }

        public async Task<Book> GetByIdAsync(int id)
        {
            return await _repo.GetByIdAsync(id);
        }

        public async Task<Book> CreateAsync(BookCreateRequest request)
        {
            var entity = new Book();
            _mapper.Map(request, entity);
            entity.CreatedAt = DateTime.Now;
            return await _repo.CreateAsync(entity);
        }

        public async Task<Book> UpdateAsync(BookUpdateReuest request)
        {
            var exist = await _repo.GetByIdAsync(request.Id);
            if (exist == null)
            {
                throw new Exception("Book not found");
            }
            _mapper.Map(request, exist);
            exist.UpdatedAt = DateTime.Now;
            return await _repo.UpdateAsync(exist);
        }

        public async Task<bool> Remove(int id)
        {
            return await _repo.Remove(id);
        }

        public async Task<bool> Active(int id)
        {
            return await _repo.Active(id);
        }

        public async Task<PagedResult<Book>> GetActiveByBookstoreAsync(int bookstoreId, int pageNo, int pageSize)
        {
            var bL = await _repo.GetActiveBookByBookstore(bookstoreId);
            var bLPaging = PagedResult<Book>.Create(bL, pageNo, pageSize);
            return bLPaging;
        }

        public async Task<PagedResult<Book>> GetInactiveByBookstoreAsync(int bookstoreId, int pageNo, int pageSize)
        {
            var bL = await _repo.GetUnactiveBookByBookStore(bookstoreId);
            var bLPaging = PagedResult<Book>.Create(bL, pageNo, pageSize);
            return bLPaging;
        }
    }
}
