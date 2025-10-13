# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy toàn bộ solution vào container
COPY . .

# Restore dependencies
RUN dotnet restore "src/ApiGateway/ApiGateway.csproj"

# Build app
RUN dotnet build "src/ApiGateway/ApiGateway.csproj" -c Release -o /app/build

# Stage 2: Publish
FROM build AS publish
RUN dotnet publish "src/ApiGateway/ApiGateway.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Copy publish output
COPY --from=publish /app/publish .

# Copy file cấu hình Ocelot nếu cần
# (chỉ cần nếu bạn không copy toàn bộ folder)
COPY src/ApiGateway/ocelot.json ./ocelot.json

EXPOSE 8080
ENTRYPOINT ["dotnet", "ApiGateway.dll"]
