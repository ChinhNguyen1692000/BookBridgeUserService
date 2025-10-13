using BookstoreService.Application.Interface;
using BookstoreService.Application.Service;
using BookstoreService.Infrastructure.DBContext;
using BookstoreService.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using AutoMapper;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// DbContext
builder.Services.AddDbContext<BookstoreDBContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("BookStoreServiceConnection")));

// AutoMapper
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

// Repository
builder.Services.AddScoped<BookstoreRepository>();

// Service
builder.Services.AddScoped<IBookstoreService, BookstoreService.Application.Service.BookstoreService>();

var app = builder.Build();

// Apply migrations automatically
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<BookstoreDBContext>();
    db.Database.Migrate();
}

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
