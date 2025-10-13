using BookService.Application.Interface;
using BookService.Application.Services;
using BookService.Infracstructure.DBContext;
using BookService.Infracstructure.Repositories;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<BookDBContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("BookServiceConnection")));


builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

builder.Services.AddScoped<IBookImageServices, BookImageServices>();
builder.Services.AddScoped<IBookTypeServices, BookTypeServices>();
builder.Services.AddScoped<IBookServices, BookServices>();

builder.Services.AddScoped<BookImageRepository>();
builder.Services.AddScoped<BookRepository>();
builder.Services.AddScoped<BookTypeRepository>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
