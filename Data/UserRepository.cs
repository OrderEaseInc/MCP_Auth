#nullable enable

using Microsoft.Data.SqlClient;
using Polly;

namespace OrderEase.DabProxy.Data;

public sealed record UserLookupResult(int Id, int CompanyId);

public interface IUserRepository
{
    Task<UserLookupResult?> FindByApiKeyAsync(Guid apiKey, CancellationToken ct = default);
}

/// <summary>
/// Looks up an OrderEase user by API key using raw ADO.NET — no EntityFramework.
/// </summary>
public class UserRepository : IUserRepository
{
    private readonly string _connectionString;
    private readonly ResiliencePipeline _sqlPipeline;

    public UserRepository(
        IConfiguration configuration,
        [FromKeyedServices("sql")] ResiliencePipeline sqlPipeline)
    {
        // Database connection: ConnectionStrings:ActiveConnection (env: ConnectionStrings__ActiveConnection)
        _connectionString = configuration["ConnectionStrings:ActiveConnection"]
            ?? throw new InvalidOperationException("ConnectionStrings:ActiveConnection is required.");
        _sqlPipeline = sqlPipeline;
    }

    /// <summary>
    /// Finds a user whose direct ApiKey matches, or who has a non-expired access token matching.
    /// Replicates the EF query:
    ///   _db.UserProfiles.Include(u => u.AccessTokens)
    ///     .SingleOrDefault(u => u.ApiKey == key || u.AccessTokens.Any(t => t.Token == key &amp;&amp; t.Expiry > UtcNow))
    /// </summary>
    public async Task<UserLookupResult?> FindByApiKeyAsync(Guid apiKey, CancellationToken ct = default)
    {
        // Table: [dbo].[Users]           — EF entity: UserProfile  ([Table("Users")] attribute)
        //   Columns used: Id (int PK), CompanyId (int), ApiKey (uniqueidentifier)
        //
        // Table: [dbo].[UserAccessTokens] — EF entity: UserAccessToken (DbSet name in context)
        //   Columns used: UserId (int FK → Users.Id), Token (uniqueidentifier), Expiry (datetime)
        const string sql = """
            SELECT TOP 1 u.Id, u.CompanyId
                FROM  mcpadmin.UserLogin u
                WHERE ApiKey = @key
            """;

        return await _sqlPipeline.ExecuteAsync<UserLookupResult?>(async innerCt =>
        {
            await using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync(innerCt);

            await using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.Add(new SqlParameter("@key", System.Data.SqlDbType.UniqueIdentifier) { Value = apiKey });

            await using var reader = await cmd.ExecuteReaderAsync(innerCt);
            if (!await reader.ReadAsync(innerCt))
                return null;

            return new UserLookupResult(
                Id:        reader.GetInt32(0),
                CompanyId: reader.GetInt32(1));
        }, ct);
    }
}
