# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy toàn bộ source code cho service
COPY . .

# Restore dependencies
RUN dotnet restore "src/Services/BookstoreService/BookstoreService.Api/BookstoreService.Api.csproj"

# Build app
RUN dotnet build "src/Services/BookstoreService/BookstoreService.Api/BookstoreService.Api.csproj" -c Release -o /app/build

# Stage 2: Publish
FROM build AS publish
RUN dotnet publish "src/Services/BookstoreService/BookstoreService.Api/BookstoreService.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .
EXPOSE 8080
ENTRYPOINT ["dotnet", "BookstoreService.Api.dll"]
