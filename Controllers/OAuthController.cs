using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using OrderEase.DabProxy.Data;
using OrderEase.DabProxy.Services;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OrderEase.DabProxy.Controllers;

[ApiController]
public class OAuthController : ControllerBase
{
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);

    // Company 1 is the internal OrderEase admin tenant.
    private const int AdminCompanyId = 1;

    private readonly IDistributedCache _cache;
    private readonly IUserRepository _users;
    private readonly IEntraIdTokenService _tokenService;

    public OAuthController(
        IDistributedCache cache,
        IUserRepository users,
        IEntraIdTokenService tokenService)
    {
        _cache        = cache;
        _users        = users;
        _tokenService = tokenService;
    }

    /// <summary>
    /// OAuth 2.1 authorization endpoint — returns a login form.
    /// The user authenticates with their OrderEase API key to grant access.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("oauth/authorize")]
    public IActionResult Authorize(
        [FromQuery(Name = "response_type")]          string responseType,
        [FromQuery(Name = "client_id")]              string clientId,
        [FromQuery(Name = "redirect_uri")]           string redirectUri,
        [FromQuery(Name = "code_challenge")]         string codeChallenge,
        [FromQuery(Name = "code_challenge_method")]  string codeChallengeMethod,
        [FromQuery(Name = "state")]                  string state,
        [FromQuery(Name = "resource")]               string? resource = null)
    {
        if (responseType != "code")
            return BadRequest(new { error = "unsupported_response_type" });

        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri) ||
            string.IsNullOrEmpty(codeChallenge) || string.IsNullOrEmpty(state))
            return BadRequest(new { error = "invalid_request" });

        return Content(
            BuildLoginHtml(clientId, redirectUri, codeChallenge, codeChallengeMethod, state, resource),
            "text/html");
    }

    /// <summary>
    /// Processes the login form. Validates the API key, stores an authorization code
    /// in the distributed cache, then redirects to the client's redirect_uri.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("oauth/authorize")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> AuthorizePost(
        [FromForm(Name = "api_key")]                 string apiKey,
        [FromForm(Name = "client_id")]               string clientId,
        [FromForm(Name = "redirect_uri")]            string redirectUri,
        [FromForm(Name = "code_challenge")]          string codeChallenge,
        [FromForm(Name = "code_challenge_method")]   string codeChallengeMethod,
        [FromForm(Name = "state")]                   string state,
        [FromForm(Name = "resource")]                string? resource = null,
        CancellationToken ct = default)
    {
        if (!Guid.TryParse(apiKey?.Trim(), out var guidKey))
            return Content(
                BuildLoginHtml(clientId, redirectUri, codeChallenge, codeChallengeMethod, state, resource, "Invalid API key format."),
                "text/html");

        var user = await _users.FindByApiKeyAsync(guidKey, ct);

        if (user is null)
            return Content(
                BuildLoginHtml(clientId, redirectUri, codeChallenge, codeChallengeMethod, state, resource, "API key not recognised."),
                "text/html");

        var code  = Guid.NewGuid().ToString("N");
        var entry = new AuthCodeEntry(
            user.Id, user.CompanyId,
            clientId, redirectUri,
            codeChallenge, codeChallengeMethod ?? "S256",
            resource);

        await _cache.SetAsync(
            $"oauth_code:{code}",
            JsonSerializer.SerializeToUtf8Bytes(entry),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = CodeLifetime },
            ct);

        var callback    = $"{redirectUri}?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state ?? "")}";
        var callbackJson = JsonSerializer.Serialize(callback);

        // Use JS navigation instead of a 302 redirect — Chrome enforces form-action CSP
        // on the full redirect chain, so a server redirect to a different origin would be
        // blocked. window.location.replace() is a navigation, not a form action.
        return Content($"""
            <!DOCTYPE html><html><head><title>Redirecting…</title></head>
            <body><script>window.location.replace({callbackJson});</script></body>
            </html>
            """, "text/html");
    }

    /// <summary>
    /// OAuth 2.1 token endpoint — exchanges an authorization code for a JWT.
    /// Validates the code, client_id, redirect_uri, and PKCE verifier.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("oauth/token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token(
        [FromForm(Name = "grant_type")]    string grantType,
        [FromForm(Name = "code")]          string code,
        [FromForm(Name = "code_verifier")] string codeVerifier,
        [FromForm(Name = "client_id")]     string clientId,
        [FromForm(Name = "redirect_uri")]  string redirectUri,
        CancellationToken ct = default)
    {
        if (grantType != "authorization_code")
            return BadRequest(new { error = "unsupported_grant_type" });

        var cacheKey    = $"oauth_code:{code}";
        var cachedBytes = await _cache.GetAsync(cacheKey, ct);
        if (cachedBytes is null)
            return BadRequest(new { error = "invalid_grant", error_description = "Authorization code not found or expired." });

        await _cache.RemoveAsync(cacheKey, ct);

        var entry = JsonSerializer.Deserialize<AuthCodeEntry>(cachedBytes)!;

        if (entry.ClientId != clientId || entry.RedirectUri != redirectUri)
            return BadRequest(new { error = "invalid_grant", error_description = "client_id or redirect_uri mismatch." });

        if (!VerifyPkce(codeVerifier, entry.CodeChallenge, entry.CodeChallengeMethod))
            return BadRequest(new { error = "invalid_grant", error_description = "PKCE verification failed." });

        var extraClaims = new[]
        {
            new Claim("userId",    entry.UserId.ToString()),
            new Claim("companyId", entry.CompanyId.ToString()),
        };

        var accessToken = _tokenService.GenerateToken(
            entry.UserId.ToString(),
            entry.CompanyId == AdminCompanyId ? "admin" : "user",
            extraClaims);

        return Ok(new
        {
            access_token = accessToken,
            token_type   = "Bearer",
            expires_in   = 3600,
        });
    }

    // ------------------------------------------------------------------ //

    private static bool VerifyPkce(string codeVerifier, string codeChallenge, string method)
    {
        if (string.IsNullOrEmpty(codeVerifier) || method != "S256")
            return false;

        var hash     = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        var computed = WebEncoders.Base64UrlEncode(hash);
        return computed == codeChallenge;
    }

    private static string BuildLoginHtml(
        string clientId, string redirectUri, string codeChallenge, string? codeChallengeMethod,
        string state, string? resource, string? error = null)
    {
        static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

        var errorBlock = error is null ? "" :
            $"""<p style="color:#dc2626;background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:.88rem">{H(error)}</p>""";

        return $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width,initial-scale=1">
              <title>OrderEase – Authorize</title>
              <style>
                *{box-sizing:border-box}
                body{font-family:system-ui,sans-serif;background:#f4f4f5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
                .card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.1);padding:40px 48px;width:100%;max-width:440px}
                h1{font-size:1.35rem;font-weight:700;margin:0 0 6px}
                .sub{color:#6b7280;font-size:.88rem;margin:0 0 26px}
                label{font-size:.85rem;font-weight:600;display:block;margin-bottom:5px;color:#374151}
                input[type=password]{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:.95rem;font-family:monospace}
                input[type=password]:focus{outline:2px solid #2563eb;border-color:transparent}
                button{margin-top:18px;width:100%;padding:11px;background:#2563eb;color:#fff;border:none;border-radius:6px;font-size:1rem;font-weight:600;cursor:pointer}
                button:hover{background:#1d4ed8}
                .hint{font-size:.78rem;color:#9ca3af;margin-top:6px}
                .client{font-size:.75rem;color:#9ca3af;margin-top:22px;padding-top:16px;border-top:1px solid #f3f4f6;word-break:break-all}
              </style>
            </head>
            <body>
              <div class="card">
                <h1>Authorize Access</h1>
                <p class="sub">Enter your OrderEase API key to grant access to this application.</p>
                {{errorBlock}}
                <form method="post" action="/oauth/authorize">
                  <input type="hidden" name="client_id"             value="{{H(clientId)}}" />
                  <input type="hidden" name="redirect_uri"          value="{{H(redirectUri)}}" />
                  <input type="hidden" name="code_challenge"        value="{{H(codeChallenge)}}" />
                  <input type="hidden" name="code_challenge_method" value="{{H(codeChallengeMethod ?? "S256")}}" />
                  <input type="hidden" name="state"                 value="{{H(state)}}" />
                  <input type="hidden" name="resource"              value="{{H(resource ?? "")}}" />
                  <label for="api_key">API Key</label>
                  <input type="password" id="api_key" name="api_key"
                         placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                         autocomplete="off" autofocus />
                  <p class="hint">Your API key can be found in your OrderEase account settings.</p>
                  <button type="submit">Authorize</button>
                </form>
                <p class="client">Requesting client:<br>{{H(clientId)}}</p>
              </div>
            </body>
            </html>
            """;
    }

    private sealed record AuthCodeEntry(
        int     UserId,
        int     CompanyId,
        string  ClientId,
        string  RedirectUri,
        string  CodeChallenge,
        string  CodeChallengeMethod,
        string? Resource);
}
