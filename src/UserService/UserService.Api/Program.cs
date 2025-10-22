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
using System.Text.Json.Serialization;
using Microsoft.OpenApi.Models;

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
builder.Services.AddScoped<ICacheService, RedisCacheService>();


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
// builder.Services.AddControllers();
// Thêm cấu hình JSON để tránh vòng lặp
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });
builder.Services.AddHttpClient();
builder.Services.AddEndpointsApiExplorer();

// Send access token in header for swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Your API Name", Version = "v1" });

    // 1. Định nghĩa Security Scheme (Security Definition)
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Vui lòng nhập Bearer Token vào trường text bên dưới. Ví dụ: 'Bearer {token}'",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer" // Phải là "Bearer"
    });

    // 2. Yêu cầu Security (Security Requirement)
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer" // Tham chiếu đến tên của Security Scheme ở trên
                }
            },
            new string[] {}
        }
    });
});


// 4. Redis
var redisConnection = builder.Configuration.GetConnectionString("Redis") ?? Environment.GetEnvironmentVariable("ConnectionStrings__Redis");

if (redisConnection != null && redisConnection.StartsWith("redis://"))
{
    redisConnection = redisConnection.Replace("redis://", "");
}

// Bắt buộc Redis phải kết nối được vì nó là dịch vụ bảo mật (JWT Blacklist)
if (string.IsNullOrEmpty(redisConnection))
{
    throw new InvalidOperationException("Redis connection string is missing.");
}

// builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
// {
//     return ConnectionMultiplexer.Connect(redisConnection);
// });

builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    if (string.IsNullOrEmpty(redisConnection))
    {
        // ❌ Không nên throw ở đây, để ứng dụng chạy tiếp và service cache sẽ lỗi khi gọi
        Console.WriteLine("❌ Redis connection string is missing. Using null connection.");
        return null!; // Trả về null hoặc một dummy object nếu IConnectionMultiplexer cho phép
    }

    try
    {
        // Thử kết nối, nếu lỗi sẽ tự động được log ra console và có thể làm crash dịch vụ Render
        return ConnectionMultiplexer.Connect(redisConnection);
    }
    catch (Exception ex)
    {
        // **NẾU BẠN MUỐN ỨNG DỤNG KHÔNG CRASH VÌ REDIS:**
        Console.WriteLine($"❌ Redis connection failed: {ex.Message}. Allowing service to start.");
        // Ghi log lỗi và return null/dummy, sau đó cacheService (RedisCacheService) phải xử lý được null này.
        return null!;
    }
});


// 5. MassTransit
// builder.Services.AddMassTransit(...)

// 6. Configure Kestrel to use Render's provided PORT
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(int.Parse(port));
});


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
    // app.UseHttpsRedirection(); // Chỉ bật trong dev
}
else
{
    // Không redirect, vì Render đã tự handle HTTP routing
    app.UseSwagger();
    app.UseSwaggerUI();
}


// app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
