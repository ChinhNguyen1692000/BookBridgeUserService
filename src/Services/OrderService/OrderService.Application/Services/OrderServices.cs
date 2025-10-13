using AutoMapper;
using Common.Paging;
using OrderService.Application.Interface;
using OrderService.Application.Models;
using OrderService.Domain.Entities;
using OrderService.Infracstructure.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OrderService.Application.Services
{
    public class OrderServices : IOrderServices
    {
        private readonly OrderRepository _repo;
        private readonly OrderItemRepository _itemRepo;
        private readonly IMapper _mapper;
        public OrderServices(OrderRepository repo, OrderItemRepository itemRepo, IMapper mapper)
        {
            _repo = repo;
            _itemRepo = itemRepo;
            _mapper = mapper;
        }
        public async Task<PagedResult<Order>> GetAll(int page, int pageSize)
        {
            var oL = await _repo.GetAllAsync();
            var oLPaging = PagedResult<Order>.Create(oL, page, pageSize);
            return oLPaging;
        }
        public async Task<Order> GetById(int id)
        {
            return await _repo.GetByIdAsync(id);
        }
        public async Task<PagedResult<Order>> GetOrderByCustomer(string customerId, int pageNo, int pageSize)
        {
            var oL = await _repo.GetOrderByCustomer(customerId);
            var oLPaging = PagedResult<Order>.Create(oL, pageNo, pageSize);
            return oLPaging;
        }
        public async Task<Order> Create(OrderCreateRequest request)
        {
            var order = _mapper.Map<Order>(request);
            order.Status = "Pending";
            order.OrderDate = DateTime.UtcNow;

            if (request.OrderItems != null && request.OrderItems.Any())
            {
                order.OrderItems = _mapper.Map<List<OrderItem>>(request.OrderItems);
            }
            return await _repo.CreateAsync(order);
        }

        public async Task<bool> Confirm(int id)
        {
            var exist = _repo.GetByIdAsync(id);
            if (exist == null)
            {
                throw new Exception("Order not found");
            }
            return await _repo.ConfirmOrder(id);
        }
        public async Task<bool> Finish(int id)
        {
            var exist = await _repo.GetByIdAsync(id);
            if (exist == null)
            {
                throw new Exception("Order not found");
            }
            exist.ShippedDate = DateTime.UtcNow;
            return await _repo.FinishOrder(id);
        }
        public async Task<bool> Cancle(int id)
        {
            var exist = await _repo.GetByIdAsync(id);
            if (exist == null)
            {
                throw new Exception("Order not found");
            }
            return await _repo.CancleOrder(id);

        }
    }
}
