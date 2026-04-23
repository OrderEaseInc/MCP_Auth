using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Polly;

namespace OrderEase.DabProxy.HealthChecks;

public sealed class RedisHealthCheck(
    IDistributedCache cache,
    ILogger<RedisHealthCheck> logger,
    [FromKeyedServices("redis")] ResiliencePipeline pipeline) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            // A Get round-trip to a missing key confirms Redis is reachable.
            await pipeline.ExecuteAsync(
                async innerCt => await cache.GetAsync("_health_probe", innerCt), ct);

            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Redis health check failed");
            return HealthCheckResult.Unhealthy("Redis unavailable");
        }
    }
}
