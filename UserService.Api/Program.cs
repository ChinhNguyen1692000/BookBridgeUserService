using UserService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using UserService.Application.Interfaces;
using UserService.Application.Services;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
// using MassTransit;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

// 1. DBContext - Đăng ký MỘT LẦN DUY NHẤT với Retry Logic
var connectionString = configuration.GetConnectionString("UserServiceConnection");
builder.Services.AddDbContext<UserDbContext>(options =>
{
    options.UseMySql(connectionString,
        new MySqlServerVersion(new Version(8, 0, 21)),
        mySqlOptions => {
            mySqlOptions.MigrationsAssembly(typeof(UserDbContext).Assembly.FullName);
            // THÊM Retry Logic: Giúp ứng dụng đợi MySQL khi khởi động Docker
            mySqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(30),
                errorNumbersToAdd: null);
        });
});

// 2. Services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
builder.Services.AddScoped<IEmailService, EmailService>();


// 3. JWT
var jwtKey = configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key is not configured.");
var jwtIssuer = configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer is not configured.");
var jwtAudience = configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience is not configured.");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// 4. MassTransit (Nếu dùng sau này)
// builder.Services.AddMassTransit(...) 

var app = builder.Build();

// Tự động áp dụng migrations VÀ XỬ LÝ LỖI
// using (var scope = app.Services.CreateScope())
// {
//     var services = scope.ServiceProvider;
//     try
//     {
//         Console.WriteLine("--> Starting database migration...");
//         var context = services.GetRequiredService<UserDbContext>();
//         context.Database.Migrate(); // Lệnh này áp dụng tất cả các migration còn thiếu
//         Console.WriteLine("--> Database migration applied successfully. Tables are ready.");
//     }
//     catch (Exception ex)
//     {
//         // Ghi log lỗi nếu migration thất bại
//         var logger = services.GetRequiredService<ILogger<Program>>();
//         logger.LogError(ex, "An error occurred during database migration.");
//     }
// }
// Tự động áp dụng migrations VÀ XỬ LÝ LỖI - Cách 2
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider; // <-- chỉ tồn tại trong scope này
    try
    {
        var context = services.GetRequiredService<UserDbContext>();
        context.Database.Migrate();
        Console.WriteLine("Database migration applied successfully.");
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred during database migration.");
    }
}


// Middleware pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
