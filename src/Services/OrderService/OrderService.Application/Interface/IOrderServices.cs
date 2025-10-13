using Common.Paging;
using OrderService.Application.Models;
using OrderService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OrderService.Application.Interface
{
    public interface IOrderServices
    {
        Task<PagedResult<Order>> GetAll(int page, int pageSize);
        Task<Order> GetById(int id);
        Task<PagedResult<Order>> GetOrderByCustomer(string customerId, int pageNo, int pageSize);
        Task<Order> Create(OrderCreateRequest request);
        Task<bool> Confirm(int id);
        Task<bool> Finish(int id);
        Task<bool> Cancle(int id);
    }
}
