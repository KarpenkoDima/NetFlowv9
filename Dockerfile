FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /repo

# Copy solution + project files first (layer cache для restore)
COPY NetFlowAnalizer.sln .
COPY src/NetFlowAnalizer.Core/NetFlowAnalizer.Core.csproj       src/NetFlowAnalizer.Core/
COPY src/NetFlowAnalizer.Infrastructure/NetFlowAnalizer.Infrastructure.csproj src/NetFlowAnalizer.Infrastructure/
COPY src/LivePipeline/LivePipeline.csproj                        src/LivePipeline/

RUN dotnet restore src/LivePipeline/LivePipeline.csproj

# Copy source and publish
COPY src/ src/
RUN dotnet publish src/LivePipeline/LivePipeline.csproj \
    -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

COPY --from=build /app/publish .

EXPOSE 5000
ENV ASPNETCORE_URLS=http://+:5000

ENTRYPOINT ["dotnet", "NetFlowAnalizer.LivePipeline.dll"]
