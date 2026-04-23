using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using OrderEase.DabProxy.Data;
using OrderEase.DabProxy.HealthChecks;
using OrderEase.DabProxy.Services;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;
using StackExchange.Redis;
using System.Threading.RateLimiting;
using Yarp.ReverseProxy.Transforms;

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

// ── Resilience pipelines (Polly) ─────────────────────────────────────────────
// Pipelines are built as singletons so the circuit-breaker state is shared
// across all consumers (UserRepository and SqlHealthCheck share one SQL circuit;
// OAuthController and RedisHealthCheck share one Redis circuit).
var sqlPipeline = new ResiliencePipelineBuilder()
    .AddRetry(new Polly.Retry.RetryStrategyOptions
    {
        ShouldHandle = new PredicateBuilder()
            .Handle<SqlException>(ex => ex.IsTransient)
            .Handle<TimeoutException>(),
        MaxRetryAttempts = 3,
        Delay            = TimeSpan.FromMilliseconds(200),
        BackoffType      = DelayBackoffType.Exponential,
        UseJitter        = true,
    })
    .AddCircuitBreaker(new Polly.CircuitBreaker.CircuitBreakerStrategyOptions
    {
        ShouldHandle = new PredicateBuilder()
            .Handle<SqlException>(ex => ex.IsTransient)
            .Handle<TimeoutException>(),
        FailureRatio      = 0.5,
        SamplingDuration  = TimeSpan.FromSeconds(30),
        MinimumThroughput = 5,
        BreakDuration     = TimeSpan.FromSeconds(15),
    })
    .Build();

var redisPipeline = new ResiliencePipelineBuilder()
    .AddRetry(new Polly.Retry.RetryStrategyOptions
    {
        ShouldHandle = new PredicateBuilder()
            .Handle<RedisConnectionException>()
            .Handle<RedisTimeoutException>(),
        MaxRetryAttempts = 2,
        Delay            = TimeSpan.FromMilliseconds(100),
        BackoffType      = DelayBackoffType.Exponential,
        UseJitter        = true,
    })
    .AddCircuitBreaker(new Polly.CircuitBreaker.CircuitBreakerStrategyOptions
    {
        ShouldHandle = new PredicateBuilder()
            .Handle<RedisConnectionException>()
            .Handle<RedisTimeoutException>(),
        FailureRatio      = 0.5,
        SamplingDuration  = TimeSpan.FromSeconds(30),
        MinimumThroughput = 3,
        BreakDuration     = TimeSpan.FromSeconds(10),
    })
    .Build();

builder.Services.AddKeyedSingleton<ResiliencePipeline>("sql",   sqlPipeline);
builder.Services.AddKeyedSingleton<ResiliencePipeline>("redis", redisPipeline);

// ── Health checks ────────────────────────────────────────────────────────────
// /health — liveness (app is running)
// /ready  — readiness (SQL + Redis reachable); used by Azure Container Apps probes
builder.Services.AddHealthChecks()
    .AddCheck<SqlHealthCheck>("sql", tags: ["ready"])
    .AddCheck<RedisHealthCheck>("redis", tags: ["ready"]);

// ── Rate limiting — 5 attempts per 10 minutes per IP on /oauth/authorize POST ─
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("authorize", httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(10),
                SegmentsPerWindow = 10,
                PermitLimit = 5,
                QueueLimit = 0,
            }));
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// ── CORS — browser-based MCP clients (e.g. MCP Inspector) make cross-origin
//    requests to these endpoints, so we allow any origin without credentials.
const string CorsPolicyName = "OAuthPublic";
builder.Services.AddCors(options =>
{
    options.AddPolicy(CorsPolicyName, policy =>
    {
        policy.AllowAnyOrigin()
              .WithMethods("GET", "POST")
              .WithHeaders("Content-Type", "Authorization");
    });
});

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

builder.Services.AddReverseProxy()
    .LoadFromMemory(routes, clusters)
    .AddTransforms(ctx =>
    {
        ctx.AddRequestTransform(transform =>
        {
            var userRole = transform.HttpContext.User.FindFirst("userRole")?.Value;
            if (!string.IsNullOrEmpty(userRole))
                transform.ProxyRequest.Headers.TryAddWithoutValidation("X-MS-API-ROLE", userRole);
            return ValueTask.CompletedTask;
        });
    });

// ── Build ───────────────────────────────────────────────────────────────────
var app = builder.Build();

// Clear KnownIPNetworks/KnownProxies so Azure Container Apps ingress headers
// are trusted. Without this only loopback is trusted, Request.Scheme stays
// "http", OIDC discovery advertises http:// endpoints, Azure redirects to
// https://, and POST→GET on the redirect converts token exchange to a GET.
var forwardedOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
};
forwardedOptions.KnownIPNetworks.Clear();
forwardedOptions.KnownProxies.Clear();
app.UseForwardedHeaders(forwardedOptions);
app.UseRateLimiter();

app.UseCors(CorsPolicyName);
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapReverseProxy();
app.MapHealthChecks("/health").AllowAnonymous();
app.MapHealthChecks("/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = r => r.Tags.Contains("ready"),
    ResultStatusCodes =
    {
        [HealthStatus.Healthy]   = StatusCodes.Status200OK,
        [HealthStatus.Degraded]  = StatusCodes.Status200OK,
        [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable,
    }
}).AllowAnonymous();

app.Run();
