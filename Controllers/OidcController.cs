using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OrderEase.DabProxy.Services;
using System.Security.Claims;

namespace OrderEase.DabProxy.Controllers;

/// <summary>
/// Exposes the OIDC discovery document, JWKS, and token-issuance endpoint
/// required for Microsoft DAB (Data API Builder) to validate RS256 JWT tokens.
///
/// Discovery endpoints are public. The token endpoint requires an existing
/// JWT Bearer token (e.g. obtained via the OAuth flow at /oauth/token).
/// </summary>
[ApiController]
public class OidcController : ControllerBase
{
    // Company 1 is the internal OrderEase admin tenant.
    private const int AdminCompanyId = 1;

    private readonly IEntraIdTokenService _tokenService;

    public OidcController(IEntraIdTokenService tokenService)
    {
        _tokenService = tokenService;
    }

    // ------------------------------------------------------------------ //
    // Public discovery endpoints — no authentication required
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Returns the OpenID Connect discovery document (RFC 8414).
    /// DAB reads this to locate the jwks_uri and validate token signatures.
    /// </summary>
    [AllowAnonymous]
    [HttpGet(".well-known/openid-configuration")]
    public IActionResult GetOpenIdConfiguration()
    {
        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        var config  = _tokenService.GetOpenIdConfiguration(baseUrl);

        return Ok(new
        {
            issuer                              = config.Issuer,
            authorization_endpoint              = $"{baseUrl}/oauth/authorize",
            token_endpoint                      = config.TokenEndpoint,
            jwks_uri                            = config.JwksUri,
            response_types_supported            = new[] { "code" },
            grant_types_supported               = new[] { "authorization_code" },
            code_challenge_methods_supported    = new[] { "S256" },
            id_token_signing_alg_values_supported = config.IdTokenSigningAlgValuesSupported,
            subject_types_supported             = config.SubjectTypesSupported,
        });
    }

    /// <summary>
    /// Returns the JSON Web Key Set containing the RSA public key used to sign tokens.
    /// DAB fetches this URI to verify token signatures.
    /// </summary>
    [AllowAnonymous]
    [HttpGet(".well-known/jwks.json")]
    public IActionResult GetJwks()
    {
        var jwks = _tokenService.GetJwks();

        return Ok(new
        {
            keys = jwks.Keys.Select(k => new
            {
                kty = k.Kty,
                use = k.Use,
                kid = k.Kid,
                alg = k.Alg,
                n   = k.N,
                e   = k.E,
            })
        });
    }

    /// <summary>
    /// RFC 9728 — OAuth 2.0 Protected Resource Metadata for the /mcp endpoint.
    /// MCP clients fetch this to discover which authorization server to use.
    /// </summary>
    [AllowAnonymous]
    [HttpGet(".well-known/oauth-protected-resource/mcp")]
    public IActionResult GetMcpProtectedResourceMetadata()
    {
        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        return Ok(new
        {
            resource                  = $"{baseUrl}/mcp",
            authorization_servers     = new[] { baseUrl },
            bearer_methods_supported  = new[] { "header" },
            scopes_supported          = Array.Empty<string>(),
        });
    }

    // ------------------------------------------------------------------ //
    // Authenticated token-issuance endpoint
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Re-issues an RS256 JWT for the caller, extracting userId/companyId from the
    /// Bearer token claims. Useful for the main API to obtain DAB-specific tokens
    /// for its already-authenticated users.
    /// </summary>
    [Authorize]
    [HttpPost("api/oidc/token")]
    public IActionResult IssueToken()
    {
        var userIdStr    = User.FindFirstValue("userId");
        var companyIdStr = User.FindFirstValue("companyId");

        if (string.IsNullOrEmpty(userIdStr) || !int.TryParse(companyIdStr, out var companyId))
            return Unauthorized();

        var extraClaims = new[]
        {
            new Claim("userId",    userIdStr),
            new Claim("companyId", companyIdStr!),
        };

        var token = _tokenService.GenerateToken(
            userIdStr,
            companyId == AdminCompanyId ? "admin" : "user",
            extraClaims);

        return Ok(new { access_token = token, token_type = "Bearer" });
    }
}
