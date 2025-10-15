# Base runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081
ENV DOTNET_ENVIRONMENT=Development

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

COPY ["Ecliptix.Core/Ecliptix.Core.csproj", "Ecliptix.Core/"]
COPY ["Ecliptix.Domain/Ecliptix.Domain.csproj", "Ecliptix.Domain/"]
COPY ["Ecliptix.Protobufs/Ecliptix.Protobufs.csproj", "Ecliptix.Protobufs/"]
COPY ["Ecliptix.Security.Certificate.Pinning/Ecliptix.Security.Certificate.Pinning.csproj", "Ecliptix.Security.Certificate.Pinning/"]
COPY ["Ecliptix.Security.Opaque/Ecliptix.Security.Opaque.csproj", "Ecliptix.Security.Opaque/"]
COPY ["Ecliptix.Utilities/Ecliptix.Utilities.csproj", "Ecliptix.Utilities/"]

COPY . .

WORKDIR "/src/Ecliptix.Core"

RUN dotnet build "./Ecliptix.Core.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Ecliptix.Core.csproj" -c $BUILD_CONFIGURATION -o /app/publish --runtime linux-x64 --self-contained false

COPY Ecliptix.Security.Certificate.Pinning/NativeLibraries/linux/libcertificate.pinning.server.so /app/publish/libecliptix.server.so

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Ecliptix.Core.dll"]
