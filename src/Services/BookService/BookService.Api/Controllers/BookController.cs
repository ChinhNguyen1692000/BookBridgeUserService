using BookService.Application.Interface;
using BookService.Application.Models;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace BookService.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BookController : ControllerBase
    {
        private readonly IBookServices _service;

        public BookController(IBookServices service)
        {
            _service = service;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll([FromQuery] int pageNo = 1, [FromQuery] int pageSize = 10)
        {
            var result = await _service.GetAllAsync(pageNo, pageSize);
            return Ok(result);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var book = await _service.GetByIdAsync(id);
            if (book == null) return NotFound();
            return Ok(book);
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] BookCreateRequest request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            var created = await _service.CreateAsync(request);
            return Ok(created);
        }

        [HttpPut]
        public async Task<IActionResult> Update([FromBody] BookUpdateReuest request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            try
            {
                var updated = await _service.UpdateAsync(request);
                return Ok(updated);
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Remove(int id)
        {
            var result = await _service.Remove(id);
            if (!result) return NotFound();
            return Ok(new { message = "Book deactivated successfully" });
        }

        [HttpPut("active/{id}")]
        public async Task<IActionResult> Active(int id)
        {
            var result = await _service.Active(id);
            if (!result) return NotFound();
            return Ok(new { message = "Book activated successfully" });
        }

        [HttpGet("active/{bookstoreId}")]
        public async Task<IActionResult> GetActiveByBookstore(int bookstoreId, int pageNo = 1, int pageSize = 10)
        {
            var result = await _service.GetActiveByBookstoreAsync(bookstoreId, pageNo, pageSize);
            return Ok(result);
        }

        [HttpGet("inactive/{bookstoreId}")]
        public async Task<IActionResult> GetInactiveByBookstore(int bookstoreId, int pageNo = 1, int pageSize = 10)
        {
            var result = await _service.GetInactiveByBookstoreAsync(bookstoreId, pageNo, pageSize);
            return Ok(result);
        }
        [HttpGet("filter")]
        public async Task<IActionResult> Filter(int? typeId, decimal? price, int pageNo = 1, int pageSize = 10)
        {
            try
            {
                var result = await _service.Filter(typeId, price, pageNo, pageSize);

                if (result == null)
                    return NotFound("No matching book found");

                return Ok(result);
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }
        [HttpGet("search")]
        public async Task<IActionResult> Search(string searchValue, int pageNo = 1, int pageSize = 10)
        {
            try
            {
                var result = await _service.Search(searchValue, pageNo, pageSize);
                if(result == null)
                {
                    return NotFound("No matching book found");
                }
                return Ok(result);
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

    }
}
