using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OrderEase.DabProxy.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;

namespace OrderEase.DabProxy.Tests;

public class EntraIdTokenServiceTests : IDisposable
{
    private readonly EntraIdTokenService _service;

    private static readonly IConfiguration Config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DabJwt:Issuer"]        = "https://test.example.com",
            ["DabJwt:Audience"]      = "test-audience",
            ["DabJwt:ExpiryMinutes"] = "60",
        })
        .Build();

    public EntraIdTokenServiceTests() => _service = new EntraIdTokenService(Config);

    public void Dispose() => _service.Dispose();

    [Fact]
    public void GenerateToken_ProducesValidRs256Jwt()
    {
        var tokenString = _service.GenerateToken("user-42", "user");

        var handler = new JwtSecurityTokenHandler();
        handler.ValidateToken(tokenString, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey        = _service.GetSigningKey(),
            ValidIssuer             = "https://test.example.com",
            ValidAudience           = "test-audience",
            ValidateLifetime        = true,
            ClockSkew               = TimeSpan.Zero,
        }, out var validated);

        var jwt = Assert.IsType<JwtSecurityToken>(validated);
        Assert.Equal(SecurityAlgorithms.RsaSha256, jwt.Header.Alg);
    }

    [Fact]
    public void GenerateToken_ContainsSubjectAndRoleClaims()
    {
        var tokenString = _service.GenerateToken("user-42", "admin");

        var token = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);

        Assert.Equal("user-42", token.Subject);
        Assert.Contains(token.Claims, c => c.Type == "userRole" && c.Value == "admin");
    }

    [Fact]
    public void GenerateToken_ExtraClaimsAppearInToken()
    {
        var extra = new[]
        {
            new Claim("userId",    "99"),
            new Claim("companyId", "7"),
        };

        var token = new JwtSecurityTokenHandler()
            .ReadJwtToken(_service.GenerateToken("user-99", "user", extra));

        Assert.Contains(token.Claims, c => c.Type == "userId"    && c.Value == "99");
        Assert.Contains(token.Claims, c => c.Type == "companyId" && c.Value == "7");
    }

    [Fact]
    public void GetJwks_ReturnsSingleRsaPublicKey()
    {
        var jwks = _service.GetJwks();

        var key = Assert.Single(jwks.Keys);
        Assert.Equal("RSA", key.Kty);
        Assert.Equal("sig", key.Use);
        Assert.Equal("RS256", key.Alg);
        Assert.False(string.IsNullOrEmpty(key.N));
        Assert.False(string.IsNullOrEmpty(key.E));
    }

    [Fact]
    public void GetOpenIdConfiguration_ReturnsEndpointsRootedAtBaseUrl()
    {
        var config = _service.GetOpenIdConfiguration("https://auth.example.com");

        Assert.Equal("https://test.example.com", config.Issuer);
        Assert.StartsWith("https://auth.example.com", config.JwksUri);
        Assert.StartsWith("https://auth.example.com", config.TokenEndpoint);
    }
}
