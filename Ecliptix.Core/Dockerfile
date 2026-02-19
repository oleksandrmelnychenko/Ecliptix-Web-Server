# Base runtime - updated to .NET 10.0
FROM mcr.microsoft.com/dotnet/aspnet:10.0-preview AS base
WORKDIR /app
EXPOSE 5051
EXPOSE 8080
EXPOSE 8081
ENV ASPNETCORE_URLS=http://+:5051
ENV DOTNET_ENVIRONMENT=Development

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0-preview AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copy project files
COPY ["nuget.config", "."]
COPY ["Directory.Build.props", "."]
COPY ["Directory.Build.targets", "."]
COPY ["Ecliptix.Core/Ecliptix.Core.csproj", "Ecliptix.Core/"]
COPY ["src/Shared/Ecliptix.SharedKernel/Ecliptix.SharedKernel.csproj", "src/Shared/Ecliptix.SharedKernel/"]
COPY ["src/Contexts/IdentityAccess/Domain/Ecliptix.IdentityAccess.Domain.csproj", "src/Contexts/IdentityAccess/Domain/"]
COPY ["src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj", "src/Contexts/IdentityAccess/Infrastructure/"]
COPY ["src/Contexts/DeviceProvisioning/Domain/Ecliptix.DeviceProvisioning.Domain.csproj", "src/Contexts/DeviceProvisioning/Domain/"]
COPY ["src/Contexts/DeviceProvisioning/Infrastructure/Ecliptix.DeviceProvisioning.Infrastructure.csproj", "src/Contexts/DeviceProvisioning/Infrastructure/"]
COPY ["src/Contexts/SecureProtocol/Domain/Ecliptix.SecureProtocol.Domain.csproj", "src/Contexts/SecureProtocol/Domain/"]
COPY ["src/Contexts/SecureProtocol/Infrastructure/Ecliptix.SecureProtocol.Infrastructure.csproj", "src/Contexts/SecureProtocol/Infrastructure/"]
COPY ["Ecliptix.Protobufs/Ecliptix.Protobufs.csproj", "Ecliptix.Protobufs/"]
COPY ["Ecliptix.Security.Certificate.Pinning/Ecliptix.Security.Certificate.Pinning.csproj", "Ecliptix.Security.Certificate.Pinning/"]
COPY ["Ecliptix.Security.Opaque/Ecliptix.Security.Opaque.csproj", "Ecliptix.Security.Opaque/"]
COPY ["src/Tools/Ecliptix.EventRouting.Generator/Ecliptix.EventRouting.Generator.csproj", "src/Tools/Ecliptix.EventRouting.Generator/"]

# Restore dependencies with GitHub credentials
RUN --mount=type=secret,id=nuget_config,target=/root/.nuget/NuGet/NuGet.Config \
    dotnet restore "Ecliptix.Core/Ecliptix.Core.csproj" || \
    (echo "Restore with mounted config failed, trying with build arg..." && \
    dotnet nuget add source https://nuget.pkg.github.com/oleksandrmelnychenko/index.json \
        --name github-ecliptix \
        --username oleksandrmelnychenko \
        --password ${GITHUB_TOKEN} \
        --store-password-in-clear-text && \
    dotnet restore "Ecliptix.Core/Ecliptix.Core.csproj")

# Copy everything else
COPY . .

# Build
WORKDIR "/src/Ecliptix.Core"
RUN dotnet build "./Ecliptix.Core.csproj" -c $BUILD_CONFIGURATION -o /app/build

# Publish stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Ecliptix.Core.csproj" \
    -c $BUILD_CONFIGURATION \
    -o /app/publish \
    --runtime linux-x64 \
    --self-contained false \
    /p:PublishSingleFile=false

# Final stage
FROM base AS final
WORKDIR /app

# Copy published files
COPY --from=publish /app/publish .

# Create logs directory
RUN mkdir -p /app/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:5051/health || exit 1

ENTRYPOINT ["dotnet", "Ecliptix.Core.dll"]
