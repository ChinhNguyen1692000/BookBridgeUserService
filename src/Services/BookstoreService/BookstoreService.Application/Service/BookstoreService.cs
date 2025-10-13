using AutoMapper;
using BookstoreService.Application.Interface;
using BookstoreService.Application.Models;
using BookstoreService.Domain.Entities;
using BookstoreService.Infrastructure.Repositories;
using Common.Paging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookstoreService.Application.Service
{
    public class BookstoreService : IBookstoreService
    {
        private readonly BookstoreRepository _repo;
        private readonly IMapper _mapper;
        public BookstoreService(BookstoreRepository repo, IMapper mapper)
        {
            _repo = repo;
            _mapper = mapper;
        }
        public async Task<PagedResult<Bookstore>> GetAllAsync(int pageNo, int pageSize)
        {
            var bsL = await _repo.GetAllAsync();
            return PagedResult<Bookstore>.Create(bsL, pageNo, pageSize);
        }
        public async Task<Bookstore> CreateAsync(BookstoreCreateRequest request)
        {
            var entity = _mapper.Map<Bookstore>(request);
            entity.OwnerId = request.OwnerId;
            entity.CreatedDate = DateTime.Now;
            entity.IsActive = true;
            return await _repo.CreateAsync(entity);
        }
        public async Task<bool> Ban(int id)
        {
            if (await _repo.GetByIdAsync(id) != null)
                return await _repo.Ban(id);
            throw new Exception("Bookstore not found");
        }
        public async Task<Bookstore> UpdateAsync(BookstoreUpdateRequest request)
        {
            var existEntity = await _repo.GetByIdAsync(request.Id);
            if (existEntity == null)
            {
                throw new Exception("Bookstore not found");
            }

            _mapper.Map(request, existEntity);
            existEntity.UpdatedAt = DateTime.Now;

            return await _repo.UpdateAsync(existEntity);
        }
        public async Task<Bookstore> GetByIdAsync(int id)
        {
            if (id == null)
                throw new Exception("Id is null");
            return await _repo.GetByIdAsync(id);
        }

    }
}
