using Common.Infrastructure.Repositories;
using OrderService.Domain.Entities;
using OrderService.Infracstructure.DBContext;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OrderService.Infracstructure.Repositories
{
    public class OrderItemRepository : BaseRepository<OrderItem, int>
    {
        public OrderItemRepository(OrderDbContext context) : base(context) { }
        public async Task<List<OrderItem>> CreateRangeAsync(List<OrderItem> oL)
        {
            await _dbSet.AddRangeAsync(oL);
            await _context.SaveChangesAsync();
            return oL;
        }
    }
}
