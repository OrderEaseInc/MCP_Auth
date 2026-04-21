using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using OrderEase.DabProxy.Data;
using OrderEase.DabProxy.Services;

var builder = WebApplication.CreateBuilder(args);

// ── Token service ───────────────────────────────────────────────────────────
// Instantiated before the DI container is built so the RSA signing key is
// available for both the service registration AND the JWT Bearer configuration.
var tokenService = new EntraIdTokenService(builder.Configuration);
builder.Services.AddSingleton<IEntraIdTokenService>(tokenService);

// ── User repository (raw ADO.NET — no EF) ───────────────────────────────────
builder.Services.AddSingleton<IUserRepository, UserRepository>();

// ── Redis distributed cache for OAuth authorization codes ───────────────────
// Config key: ConnectionStrings:RedisConnection  (env: ConnectionStrings__RedisConnection)
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration["ConnectionStrings:RedisConnection"]
        ?? throw new InvalidOperationException("ConnectionStrings:RedisConnection is required.");
    options.InstanceName = "DabProxy";
});

// ── JWT Bearer auth (validates tokens issued by this service) ────────────────
// The /api/oidc/token endpoint requires a valid Bearer token with userId/companyId claims.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["DabJwt:Issuer"] ?? "https://api.orderease.com",
            ValidateAudience = true,
            ValidAudience = builder.Configuration["DabJwt:Audience"] ?? "dab",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = tokenService.GetSigningKey(),
        };
    });

builder.Services.AddAuthorization();

// ── Controllers (no camelCase — OIDC spec requires snake_case property names) ─
builder.Services.AddControllers().AddJsonOptions(opts =>
{
    opts.JsonSerializerOptions.PropertyNamingPolicy = null;
});

// ── YARP Reverse Proxy: forward /mcp traffic to Microsoft DAB ────────────────
// Config key: McpProxy:DestinationUrl  (env: McpProxy__DestinationUrl)
var mcpDestination = builder.Configuration.GetValue<string>("McpProxy:DestinationUrl")
    ?? "https://oe-dab-mcp.yellowpebble-983ae191.eastus2.azurecontainerapps.io/";

var routes = new[]
{
    new Yarp.ReverseProxy.Configuration.RouteConfig
    {
        RouteId   = "mcp-subpath",
        ClusterId = "mcp",
        Match     = new Yarp.ReverseProxy.Configuration.RouteMatch { Path = "/mcp/{**catch-all}" }
    },
    new Yarp.ReverseProxy.Configuration.RouteConfig
    {
        RouteId   = "mcp-root",
        ClusterId = "mcp",
        Match     = new Yarp.ReverseProxy.Configuration.RouteMatch { Path = "/mcp" }
    },
};

var clusters = new[]
{
    new Yarp.ReverseProxy.Configuration.ClusterConfig
    {
        ClusterId    = "mcp",
        Destinations = new Dictionary<string, Yarp.ReverseProxy.Configuration.DestinationConfig>
        {
            ["primary"] = new() { Address = mcpDestination }
        }
    }
};

builder.Services.AddReverseProxy().LoadFromMemory(routes, clusters);

// ── Build ───────────────────────────────────────────────────────────────────
var app = builder.Build();

// Trust X-Forwarded-For / X-Forwarded-Proto from the container ingress so that
// Request.Scheme and Request.Host are correct in the OIDC discovery document.
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapReverseProxy();

app.Run();
