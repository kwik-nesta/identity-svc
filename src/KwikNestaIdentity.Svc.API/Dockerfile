FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["src/KwikNestaIdentity.Svc.API/KwikNestaIdentity.Svc.API.csproj", "src/KwikNestaIdentity.Svc.API/"]
COPY ["src/KwikNestaIdentity.Svc.Application/KwikNestaIdentity.Svc.Application.csproj", "src/KwikNestaIdentity.Svc.Application/"]
COPY ["src/KwikNestaIdentity.Svc.Contract/KwikNestaIdentity.Svc.Contract.csproj", "src/KwikNestaIdentity.Svc.Contract/"]
COPY ["src/KwikNestaIdentity.Svc.Domain/KwikNestaIdentity.Svc.Domain.csproj", "src/KwikNestaIdentity.Svc.Domain/"]
COPY ["src/KwikNestaIdentity.Svc.Infrastructure/KwikNestaIdentity.Svc.Infrastructure.csproj", "src/KwikNestaIdentity.Svc.Infrastructure/"]
RUN dotnet restore "./src/KwikNestaIdentity.Svc.API/KwikNestaIdentity.Svc.API.csproj"

COPY . .
WORKDIR "/src/src/KwikNestaIdentity.Svc.API"
RUN dotnet build "./KwikNestaIdentity.Svc.API.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./KwikNestaIdentity.Svc.API.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "KwikNestaIdentity.Svc.API.dll"]