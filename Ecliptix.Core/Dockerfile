FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081
ENV DOTNET_ENVIRONMENT=Development

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Ecliptix.Core/Ecliptix.Core.csproj", "Ecliptix.Core/"]
COPY ["Ecliptix.Domain/Ecliptix.Domain.csproj", "Ecliptix.Domain/"]
COPY ["Ecliptix.Security.SSL.Native/Ecliptix.Security.SSL.Native.csproj", "Ecliptix.Security.SSL.Native/"]
COPY ["Ecliptix.Security.Opaque/Ecliptix.Security.Opaque.csproj", "Ecliptix.Security.Opaque/"]
RUN dotnet restore "Ecliptix.Core/Ecliptix.Core.csproj"
COPY . .
WORKDIR "/src/Ecliptix.Core"
RUN dotnet build "./Ecliptix.Core.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Ecliptix.Core.csproj" -c $BUILD_CONFIGURATION -o /app/publish --runtime linux-x64 --self-contained false
# For demonstration purposes, create a stub native library since we don't have the Linux .so
# In production, this would be replaced with the actual compiled Linux native library
RUN touch /app/publish/libecliptix.server.so

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Ecliptix.Core.dll"]
