# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy all source code for the entire OrderService
COPY . .

# Restore dependencies
RUN dotnet restore "src/Services/OrderService/OrderService.Api/OrderService.Api.csproj"

# Build the application
RUN dotnet build "src/Services/OrderService/OrderService.Api/OrderService.Api.csproj" -c Release -o /app/build

# Stage 2: Publish
FROM build AS publish
RUN dotnet publish "src/Services/OrderService/OrderService.Api/OrderService.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Final runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .
EXPOSE 8080
ENTRYPOINT ["dotnet", "OrderService.Api.dll"]
