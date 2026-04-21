#nullable enable

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace OrderEase.DabProxy.Services;

/// <summary>
/// Generates RS256-signed JWTs and exposes the JWKS / OIDC discovery data needed
/// for Microsoft DAB to validate tokens.
///
/// Registered as a singleton so the RSA key pair is stable for the process lifetime.
/// In production, set DabJwt:RsaPrivateKeyPemBase64 in environment variables to a
/// base64-encoded DER PKCS#8 private key so the key survives container restarts.
/// When multiple instances run behind a load-balancer ALL instances must share the
/// same key — set DabJwt:RsaPrivateKeyPemBase64 to the same value in every instance.
/// </summary>
public class EntraIdTokenService : IEntraIdTokenService, IDisposable
{
    private readonly RSA _rsa;
    private readonly string _kid;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _expiryMinutes;
    private readonly RsaSecurityKey _signingKey;
    private readonly JwksDocument _cachedJwks;

    private static readonly JwtSecurityTokenHandler _jwtHandler = new();

    public EntraIdTokenService(IConfiguration configuration)
    {
        var section = configuration.GetSection("DabJwt");

        _issuer        = section["Issuer"]        ?? "https://api.orderease.com";
        _audience      = section["Audience"]      ?? "dab";
        _expiryMinutes = section.GetValue<int?>("ExpiryMinutes") ?? 60;

        // DabJwt:RsaPrivateKeyPemBase64 — base64-encoded raw PKCS#8 DER private key bytes.
        // Generate with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0
        var pemKeyBase64 = section["RsaPrivateKeyPemBase64"];
        if (!string.IsNullOrWhiteSpace(pemKeyBase64))
        {
            var keyBytes = Convert.FromBase64String(pemKeyBase64);
            _rsa = RSA.Create();
            _rsa.ImportRSAPrivateKey(keyBytes, out _);
        }
        else
        {
            // Auto-generate ephemeral key — tokens are invalid after container restart.
            _rsa = RSA.Create(2048);
        }

        var publicParams = _rsa.ExportParameters(false);
        if (publicParams.Modulus == null || publicParams.Exponent == null)
            throw new InvalidOperationException("RSA key export produced null Modulus or Exponent.");

        _kid        = ComputeKid(publicParams);
        _signingKey = new RsaSecurityKey(_rsa) { KeyId = _kid };
        _cachedJwks = BuildJwks(publicParams, _kid);
    }

    public string GenerateToken(string subject, string role, Claim[]? extraClaims = null)
    {
        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new("roles", role),
        };

        if (extraClaims != null) claims.AddRange(extraClaims);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(
                claims,
                authenticationType: "custom",
                nameType: ClaimTypes.NameIdentifier,
                roleType: "roles"),
            Issuer             = _issuer,
            Audience           = _audience,
            IssuedAt           = now,
            NotBefore          = now,
            Expires            = now.AddMinutes(_expiryMinutes),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
        };

        var token = _jwtHandler.CreateJwtSecurityToken(descriptor);
        token.Header[JwtHeaderParameterNames.Kid] = _kid;

        return _jwtHandler.WriteToken(token);
    }

    public JwksDocument         GetJwks()                           => _cachedJwks;
    public RsaSecurityKey       GetSigningKey()                     => _signingKey;

    public OpenIdConfiguration GetOpenIdConfiguration(string issuerBaseUrl)
    {
        var baseUrl = issuerBaseUrl.TrimEnd('/');
        return new OpenIdConfiguration
        {
            Issuer                           = _issuer,
            JwksUri                          = $"{baseUrl}/.well-known/jwks.json",
            TokenEndpoint                    = $"{baseUrl}/oauth/token",
            IdTokenSigningAlgValuesSupported = new[] { "RS256" },
            ResponseTypesSupported           = new[] { "token" },
            SubjectTypesSupported            = new[] { "public" },
        };
    }

    public void Dispose() => _rsa.Dispose();

    private static string ComputeKid(RSAParameters pub)
    {
        var combined = new byte[pub.Modulus!.Length + pub.Exponent!.Length];
        pub.Modulus.CopyTo(combined, 0);
        pub.Exponent.CopyTo(combined, pub.Modulus.Length);
        return Convert.ToHexString(SHA256.HashData(combined), 0, 8).ToLowerInvariant();
    }

    private static JwksDocument BuildJwks(RSAParameters pub, string kid) =>
        new()
        {
            Keys = new List<JwkKey>
            {
                new()
                {
                    Kty = "RSA",
                    Use = "sig",
                    Alg = "RS256",
                    Kid = kid,
                    N   = Base64UrlEncoder.Encode(pub.Modulus),
                    E   = Base64UrlEncoder.Encode(pub.Exponent),
                }
            }
        };
}
