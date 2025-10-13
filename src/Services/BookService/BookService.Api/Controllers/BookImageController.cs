using BookService.Application.Services;
using BookService.Application.Models;
using BookService.Domain.Entities;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using BookService.Application.Interface;

namespace BookService.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BookImageController : ControllerBase
    {
        private readonly IBookImageServices _service;

        public BookImageController(IBookImageServices service)
        {
            _service = service;
        }

        // GET: api/BookImage
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var images = await _service.GetAllAsync();
            return Ok(images);
        }

        // GET: api/BookImage/{id}
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var image = await _service.GetByBookIdAsync(id);
            if (image == null) return NotFound();
            return Ok(image);
        }

        // POST: api/BookImage
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] BookImageCreateRequest request)
        {
            var created = await _service.CreateAsync(request);
            return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
        }

        // PUT: api/BookImage/{id}
        [HttpPut]
        public async Task<IActionResult> Update([FromBody] BookImageUpdateRequest request)
        {
            try
            {
                var updated = await _service.UpdateAsync(request);
                return Ok(updated);
            }
            catch (System.Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }

        // DELETE: api/BookImage/{id}
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var deleted = await _service.DeleteAsync(id);
            if (!deleted) return NotFound();
            return NoContent();
        }
    }
}
