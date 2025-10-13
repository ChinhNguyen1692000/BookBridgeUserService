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
    public class BookImageRepository : BaseRepository<BookImage, int>
    {
        public BookImageRepository(BookDBContext context) : base(context) { }
        public async Task<List<BookImage>> GetByBookId(int bookId)
        {
            return await _dbSet.Where(bi => bi.BookId == bookId).ToListAsync();
        }
    }
    
}
