using Common.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using OrderService.Domain.Entities;
using OrderService.Infracstructure.DBContext;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OrderService.Infracstructure.Repositories
{
    public class OrderRepository : BaseRepository<Order, int>
    {
        public OrderRepository(OrderDbContext context) : base(context) { }
        public async Task<List<Order>> GetOrderByCustomer(string customerId)
        {
            return await _dbSet.Include(o => o.OrderItems).Where(o => o.CustomerId.Equals(customerId)).ToListAsync();
        }
        public async Task<Order> GetByIdAsync(int id)
        {
            return await _dbSet.Include(o => o.OrderItems).FirstOrDefaultAsync(o => o.Id == id);
        }
        public async Task<List<Order>> GetAllAsync()
        {
            return await _dbSet.Include(o => o.OrderItems).ToListAsync();
        }
        public async Task<bool> ConfirmOrder(int id)
        {
            var o = await _dbSet.FirstOrDefaultAsync(o => o.Id == id);
            o.Status = "Confirmed";
            await _context.SaveChangesAsync();
            return o.Status.Equals("Confirmed");
        }
        public async Task<bool> FinishOrder(int id)
        {
            var o = await _dbSet.FirstOrDefaultAsync(o => o.Id == id);
            o.Status = "Finish";
            await _context.SaveChangesAsync();
            return o.Status.Equals("Finish");
        }
        public async Task<bool> CancleOrder(int id)
        {
            var o = await _dbSet.FirstOrDefaultAsync(o => o.Id == id);
            o.Status = "Cancle";
            await _context.SaveChangesAsync();
            return o.Status.Equals("Cancle");
        }
        public async Task<Order> CreateAsync(Order order)
        {
            string orderNum;
            var last = await _dbSet.OrderByDescending(o => o.Id).FirstOrDefaultAsync();
            if (last == null)
            {
                orderNum = "O1";
            }
            else
            {
                var lastOrderNumber = last.OrderNumber;
                int num = int.Parse(lastOrderNumber.Substring(1)) + 1;
                orderNum = "O" + num;
            }
            order.OrderNumber = orderNum;
            try
            {
                await _dbSet.AddAsync(order);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
            return order;
        }

    }
}
