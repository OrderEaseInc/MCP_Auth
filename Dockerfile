FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS base
WORKDIR /app
EXPOSE 8080
RUN apk add --no-cache icu-libs
ENV DOTNET_GLOBALIZATION_INVARIANT=false

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["OrderEase.DabProxy.csproj", "."]
RUN dotnet restore "OrderEase.DabProxy.csproj"
COPY . .
RUN dotnet publish "OrderEase.DabProxy.csproj" -c Release -o /app/publish --no-restore

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "OrderEase.DabProxy.dll"]
