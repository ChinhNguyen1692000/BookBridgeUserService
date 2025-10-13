using AutoMapper;
using BookService.Application.Interface;
using BookService.Application.Models;
using BookService.Domain.Entities;
using BookService.Infracstructure.Repositories;
using BookstoreService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BookService.Application.Services
{
    public class BookImageServices : IBookImageServices
    {
        private readonly BookImageRepository _repo;
        private readonly IMapper _mapper;

        public BookImageServices(BookImageRepository repo, IMapper mapper)
        {
            _repo = repo;
            _mapper = mapper;
        }

        public async Task<BookImage> CreateAsync(BookImageCreateRequest request)
        {
            var entity = _mapper.Map<BookImage>(request);
            entity.UploadedAt = DateTime.Now;
            return await _repo.CreateAsync(entity);
        }

        public async Task<BookImage> UpdateAsync(BookImageUpdateRequest request)
        {
            var entity = await _repo.GetByIdAsync(request.Id);
            if (entity == null)
                throw new Exception($"BookImage not found");

            _mapper.Map(request, entity);
            entity.UploadedAt = DateTime.Now;
            return await _repo.UpdateAsync(entity);
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var entity = await _repo.GetByIdAsync(id);
            if (entity == null)
                return false;

            await _repo.DeleteAsync(entity);
            return true;
        }

        public async Task<IEnumerable<BookImage>> GetAllAsync()
        {
            return await _repo.GetAllAsync();
        }

        public async Task<BookImage> GetByBookIdAsync(int bookId)
        {
            return await _repo.GetByIdAsync(bookId);
        }
    }
}
