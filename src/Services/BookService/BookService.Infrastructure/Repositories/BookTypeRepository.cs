using BookService.Domain.Entities;
using BookService.Infracstructure.DBContext;
using Common.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Infracstructure.Repositories
{
    public class BookTypeRepository : BaseRepository<BookType, int>
    {
        public BookTypeRepository(BookDBContext context) : base(context) { }
        public async Task<bool> Remove(int id)
        {
            var entity = await _dbSet.FirstOrDefaultAsync(bt => bt.Id == id);
            entity.isActive = false;
            await _context.SaveChangesAsync();
            return !entity.isActive;
        }
        public async Task<bool> Active(int id)
        {
            var entity = await _dbSet.FirstOrDefaultAsync(bt => bt.Id == id);
            entity.isActive = true;
            await _context.SaveChangesAsync();
            return entity.isActive;
        }
        public async Task<List<BookType>> GetActiveType()
        {
            return await _dbSet.Where(bt => bt.isActive).ToListAsync();
        }
        public async Task<List<BookType>> GetUnactiveType()
        {
            return await _dbSet.Where(bt => !bt.isActive).ToListAsync();
        }
    }
}
