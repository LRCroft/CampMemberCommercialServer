# Base runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 443
ENV ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
ENV ASPNETCORE_URLS=https://+:443

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src/campmember_commercial_webapp_linuximg

# Copy project files
COPY campmember_commercial_webapp_linuximg/. .

# Restore, build, publish
RUN dotnet restore "campmember_commercial_webapp_linuximg.csproj"
RUN dotnet build "campmember_commercial_webapp_linuximg.csproj" -c $BUILD_CONFIGURATION -o /app/build /p:UseAppHost=false
RUN dotnet publish "campmember_commercial_webapp_linuximg.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM base AS final
WORKDIR /app

# Copy published output only
COPY --from=build /app/publish .

# Copy PEM file for runtime if needed
COPY campmember_commercial_webapp_linuximg/Credentials/croftteams@camppasswordmanager.com-2025-08-06T21_03_11.835Z.pem /app/

ENTRYPOINT ["dotnet", "campmember_commercial_webapp_linuximg.dll"]