using BookService.Application.Interface;
using BookService.Application.Models;
using BookService.Application.Services;
using BookService.Domain.Entities;
using Microsoft.AspNetCore.Mvc;

namespace BookService.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BookTypeController : ControllerBase
    {
        private readonly IBookTypeServices _service;

        public BookTypeController(IBookTypeServices service)
        {
            _service = service;
        }

        // ---- Get all ----
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var result = await _service.GetAllAsync();
            return Ok(result);
        }

        // ---- Get by Id ----
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var bookType = await _service.GetByIdAsync(id);
            if (bookType == null)
                return NotFound(new { message = $"BookType with Id {id} not found." });

            return Ok(bookType);
        }

        // ---- Create ----
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] BookTypeCreateRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var created = await _service.CreateAsync(request);
            return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
        }

        // ---- Update ----
        [HttpPut]
        public async Task<IActionResult> Update([FromBody] BookTypeUpdateRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

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

        // ---- Delete (soft/hard tùy repo) ----
        [HttpDelete("{id}")]
        public async Task<IActionResult> Remove(int id)
        {
            var result = await _service.Remove(id);
            if (!result)
                return NotFound(new { message = $"BookType with Id {id} not found." });

            return Ok(new { success = true });
        }

        // ---- Active (undo soft delete) ----
        [HttpPatch("{id}/active")]
        public async Task<IActionResult> Active(int id)
        {
            var result = await _service.Active(id);
            if (!result)
                return NotFound(new { message = $"BookType with Id {id} not found." });

            return Ok(new { success = true });
        }
        [HttpGet("/active")]
        public async Task<IActionResult> GetActiveType()
        {
            var result = _service.GetActiveType();
            return Ok(result);
        }
        [HttpGet("/unactive")]
        public async Task<IActionResult> GetUnactiveType()
        {
            var result = _service.GetUnactiveType();
            return Ok(result);
        }

    }
}
