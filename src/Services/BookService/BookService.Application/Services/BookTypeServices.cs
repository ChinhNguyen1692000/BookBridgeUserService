using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using BookService.Application.Interface;
using BookService.Application.Models;
using BookService.Domain.Entities;
using BookService.Infracstructure.Repositories;

namespace BookService.Application.Services
{
    public class BookTypeServices : IBookTypeServices
    {
        private readonly BookTypeRepository _repo;
        private readonly IMapper _mapper;

        public BookTypeServices(BookTypeRepository repo, IMapper mapper)
        {
            _repo = repo;
            _mapper = mapper;
        }

        // ---- Create ----
        public async Task<BookType> CreateAsync(BookTypeCreateRequest request)
        {
            var entity = _mapper.Map<BookType>(request);
            entity.isActive = true;

            return await _repo.CreateAsync(entity);
        }

        // ---- Update ----
        public async Task<BookType> UpdateAsync(BookTypeUpdateRequest request)
        {
            var exist = await _repo.GetByIdAsync(request.Id);
            if (exist == null)
                throw new Exception($"BookType not found.");

            _mapper.Map(request, exist);

            return await _repo.UpdateAsync(exist);
        }

        // ---- Delete (hard) ----
        public async Task<bool> Remove(int id)
        {
            var exist = await _repo.GetByIdAsync(id);
            if (exist == null)
                return false;

            return await _repo.Remove(id);
        }
        public async Task<bool> Active(int id)
        {
            var exist = await _repo.GetByIdAsync(id);
            if (exist == null)
                return false;

            return await _repo.Active(id);
        }
        public async Task<List<BookType>> GetActiveType()
        {
            return await _repo.GetActiveType();
        }
        public async Task<List<BookType>> GetUnactiveType()
        {
            return await _repo.GetUnactiveType();
        }

        // ---- Get all ----
        public async Task<List<BookType>> GetAllAsync()
        {
            return await _repo.GetAllAsync();
        }

        // ---- Get by Id ----
        public async Task<BookType?> GetByIdAsync(int id)
        {
            return await _repo.GetByIdAsync(id);
        }
    }
}
