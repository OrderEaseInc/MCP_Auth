#nullable enable

using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace OrderEase.DabProxy.Services;

public interface IEntraIdTokenService
{
    string GenerateToken(string subject, string role, Claim[]? extraClaims = null);
    JwksDocument GetJwks();
    OpenIdConfiguration GetOpenIdConfiguration(string issuerBaseUrl);
    RsaSecurityKey GetSigningKey();
}

public class JwksDocument
{
    public List<JwkKey> Keys { get; set; } = new();
}

public class JwkKey
{
    public string Kty { get; set; } = default!;
    public string Use { get; set; } = default!;
    public string Kid { get; set; } = default!;
    public string Alg { get; set; } = default!;
    public string N   { get; set; } = default!;
    public string E   { get; set; } = default!;
}

public class OpenIdConfiguration
{
    public string   Issuer                             { get; set; } = default!;
    public string   JwksUri                            { get; set; } = default!;
    public string   TokenEndpoint                      { get; set; } = default!;
    public string[] IdTokenSigningAlgValuesSupported   { get; set; } = default!;
    public string[] ResponseTypesSupported             { get; set; } = default!;
    public string[] SubjectTypesSupported              { get; set; } = default!;
}
