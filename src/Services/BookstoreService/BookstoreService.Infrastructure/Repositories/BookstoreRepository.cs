using BookstoreService.Domain.Entities;
using BookstoreService.Infrastructure.DBContext;
using Common.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;

namespace BookstoreService.Infrastructure.Repositories
{
    public class BookstoreRepository : BaseRepository<Bookstore, int>
    {
        public BookstoreRepository(BookstoreDBContext context) : base(context)
        {
        }
        public async Task<bool> Ban(int id)
        {
            var bs = await _dbSet.FirstOrDefaultAsync(x => x.Id == id);
            bs.IsActive = false;
            await _context.SaveChangesAsync();
            return !bs.IsActive;
        }
    }
}
