using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Polly;

namespace OrderEase.DabProxy.HealthChecks;

public sealed class SqlHealthCheck(
    IConfiguration configuration,
    ILogger<SqlHealthCheck> logger,
    [FromKeyedServices("sql")] ResiliencePipeline pipeline) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            await pipeline.ExecuteAsync(async innerCt =>
            {
                var connStr = configuration["ConnectionStrings:ActiveConnection"]
                    ?? throw new InvalidOperationException("ConnectionStrings:ActiveConnection is missing.");

                await using var conn = new SqlConnection(connStr);
                await conn.OpenAsync(innerCt);
                await using var cmd = new SqlCommand("SELECT 1", conn);
                await cmd.ExecuteScalarAsync(innerCt);
            }, ct);

            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "SQL health check failed");
            return HealthCheckResult.Unhealthy("SQL unavailable");
        }
    }
}
