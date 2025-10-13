using BookService.Domain.Entities;
using BookService.Infracstructure.DBContext;
using Common.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Infracstructure.Repositories
{
    public class BookRepository : BaseRepository<Book, int>
    {
        public BookRepository(BookDBContext context) : base(context) { }
        public async Task<bool> Remove(int id)
        {
            var entity = await _dbSet.FirstOrDefaultAsync(x => x.Id == id);
            entity.IsActive = false;
            await _context.SaveChangesAsync();
            return !entity.IsActive;
        }
        public async Task<bool> Active(int id)
        {
            var entity = await _dbSet.FirstOrDefaultAsync(x => x.Id == id);
            entity.IsActive = true;
            await _context.SaveChangesAsync();
            return entity.IsActive;
        }
        public async Task<List<Book>> GetActiveBookByBookstore(int id)
        {
            return await _dbSet.Include(b => b.BookType).Where(b => b.IsActive && b.BookstoreId == id).ToListAsync();
        }
        public async Task<List<Book>> GetUnactiveBookByBookStore(int id)
        {
            return await _dbSet.Include(b => b.BookType).Where(b => !b.IsActive && b.BookstoreId == id).ToListAsync();
        }
        public async Task<Book> GetByIdAsync(int id)
        {
            return await _dbSet.Include(b => b.BookType).Include(b => b.BookImages).FirstOrDefaultAsync(b => b.Id == id);
        }
        public async Task<List<Book>> Filter(int? typeId, decimal? price)
        {
            return await _dbSet.Include(b => b.BookType).Where(b =>
            (typeId != null && b.TypeId == typeId) ||
            (price.HasValue && b.Price <= price) &&
            (b.IsActive)).ToListAsync();
        }
        public async Task<List<Book>> GetAlAsync()
        {
            return await _dbSet.Include(b => b.BookType).Where(b => b.IsActive).ToListAsync();
        }
        public async Task<List<Book>> SearchByTitleOrAuthor(string? searchValue)
        {
            var bL = _dbSet.Include(b => b.BookType).Where(b => b.IsActive).AsQueryable();
            if (!searchValue.IsNullOrEmpty())
            {
                bL =  bL.Where(b => b.Title.ToLower().Contains(searchValue.ToLower()) || b.Author.ToLower().Contains(searchValue.ToLower()));
            }
            return await bL.ToListAsync();
        }
    }
}
