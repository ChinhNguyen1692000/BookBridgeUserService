using UserService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using UserService.Application.Interfaces;
using UserService.Application.Services;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using UserService.Application.Configurations;
using UserService.Domain.Entities;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using StackExchange.Redis;

// using MassTransit;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

// 1. DBContext - Đăng ký MỘT LẦN DUY NHẤT với Retry Logic
var connectionString = configuration.GetConnectionString("UserServiceConnection");
builder.Services.AddDbContext<UserDbContext>(options =>
{
    options.UseNpgsql(connectionString, npgsqlOptions =>
    {
        npgsqlOptions.MigrationsAssembly(typeof(UserDbContext).Assembly.FullName);
        npgsqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorCodesToAdd: null);
    });
});

// 2. Services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.Configure<GoogleAuthSettings>(
    builder.Configuration.GetSection("GoogleAuth"));
builder.Services.AddScoped<IPasswordGenerator, PasswordGenerator>();
builder.Services.AddScoped<IOTPService, OTPService>();


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
        IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        NameClaimType = "nameid"
    };

    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var jti = context.Principal.FindFirstValue(JwtRegisteredClaimNames.Jti);

            if (string.IsNullOrEmpty(jti))
            {
                context.Fail("JWT missing jti.");
                return;
            }

            var cacheService = context.HttpContext.RequestServices.GetRequiredService<ICacheService>();

            if (await cacheService.IsBlacklistedAsync(jti))
            {
                context.Fail("This token has been revoked.");
            }

            await Task.CompletedTask;
        }
    };

});

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


// 4. Redis
var redisConnection = builder.Configuration.GetConnectionString("Redis") ?? "localhost:6379";
builder.Services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(redisConnection));
builder.Services.AddScoped<ICacheService, RedisCacheService>();

// 5. MassTransit (Nếu dùng sau này)
// builder.Services.AddMassTransit(...) 

var app = builder.Build();


// Tự động áp dụng migrations VÀ XỬ LÝ LỖI - Cách 2
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider; // <-- chỉ tồn tại trong scope này
    try
    {
        // Lấy DbContext đã đăng ký
        var context = services.GetRequiredService<UserDbContext>();

        // Tự động áp dụng migration
        context.Database.Migrate();


        // ----- Seed Admin Account -----
        if (!context.Users.Any(u => u.Username == "admin"))
        {
            var passwordHasher = services.GetRequiredService<IPasswordHasher>();

            // Tạo admin user mới
            var adminUser = new User
            {
                Id = Guid.NewGuid(),
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = passwordHasher.HashPassword("Admin@123"),
                IsActive = true,
                IsGoogleUser = false,
                CreatedAt = DateTime.UtcNow
            };

            // Thêm admin user vào database
            context.Users.Add(adminUser);

            // Gán role Admin (role đã seed sẵn trong OnModelCreating)
            var adminRole = context.Roles.FirstOrDefault(r => r.RoleName == "Admin");
            if (adminRole != null)
            {
                context.UserRoles.Add(new UserRole
                {
                    UserId = adminUser.Id,
                    RoleId = adminRole.Id
                });
            }

            // Lưu thay đổi vào database
            context.SaveChanges();
            // Seed Admin Account xong -------
            Console.WriteLine("Admin account created.");
        }
        // -------------------------------
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
