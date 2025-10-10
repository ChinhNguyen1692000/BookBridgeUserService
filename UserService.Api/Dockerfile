# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy the solution file and restore dependencies (assuming your sln is in the root)
COPY ["UserService.Api/UserService.Api.csproj", "UserService.Api/"]
COPY ["UserService.Application/UserService.Application.csproj", "UserService.Application/"]
COPY ["UserService.Domain/UserService.Domain.csproj", "UserService.Domain/"]
COPY ["UserService.Infrastructure/UserService.Infrastructure.csproj", "UserService.Infrastructure/"]
RUN dotnet restore "UserService.Api/UserService.Api.csproj"

# Copy all the remaining source code
COPY . .
WORKDIR "/src/UserService.Api"
RUN dotnet build "UserService.Api.csproj" -c Release -o /app/build

# Stage 2: Publish the application
FROM build AS publish
RUN dotnet publish "UserService.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Create the final image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .
EXPOSE 8080
ENTRYPOINT ["dotnet", "UserService.Api.dll"]