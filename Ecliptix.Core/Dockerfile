FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
USER $APP_UID
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_ENVIRONMENT=Deployment

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Ecliptix.Core/Ecliptix.Core.csproj", "Ecliptix.Core/"]
COPY ["Ecliptix.Domain/Ecliptix.Domain.csproj", "Ecliptix.Domain/"]
RUN dotnet restore "Ecliptix.Core/Ecliptix.Core.csproj"
COPY . .
WORKDIR "/src/Ecliptix.Core"
RUN dotnet build "./Ecliptix.Core.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Ecliptix.Core.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Ecliptix.Core.dll"]
