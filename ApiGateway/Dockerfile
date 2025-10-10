# Stage 1: Build the application
# Sử dụng .NET SDK 8.0 để build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution file và các project cần thiết
# Thay đổi UserService.Api thành Bookbridge.ApiGateway
COPY ["ApiGateway/ApiGateway.csproj", "ApiGateway/"]

# Restore dependencies
RUN dotnet restore "ApiGateway/ApiGateway.csproj"

# Copy tất cả source code còn lại
COPY . .
WORKDIR "/src/ApiGateway"

# Build ứng dụng
RUN dotnet build "ApiGateway.csproj" -c Release -o /app/build

# Stage 2: Publish the application
FROM build AS publish
# Publish ứng dụng
RUN dotnet publish "ApiGateway.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Create the final image
# Sử dụng .NET ASPNET Runtime 8.0 nhỏ gọn để chạy
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Copy các file đã publish
COPY --from=publish /app/publish .

# Cần đảm bảo file cấu hình Ocelot.json đã được copy vào thư mục gốc /app
# Nếu file ocelot.json nằm trong thư mục Bookbridge.ApiGateway, bạn có thể copy nó từ đó:
# LƯU Ý: Nếu ocelot.json của bạn nằm trong thư mục gốc của repo (ví dụ: bookbridge-backend), bạn cần chỉnh lại đường dẫn
# Dòng này giả định ocelot.json nằm cùng cấp với Bookbridge.ApiGateway.csproj
# COPY ["Bookbridge.ApiGateway/ocelot.json", "."] 


EXPOSE 8080
# Đặt điểm vào là ApiGateway.dll
ENTRYPOINT ["dotnet", "ApiGateway.dll"]
