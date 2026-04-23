using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OrderEase.DabProxy.Controllers;
using OrderEase.DabProxy.Data;
using OrderEase.DabProxy.Services;
using Polly;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace OrderEase.DabProxy.Tests;

public class OAuthControllerTests
{
    private readonly Mock<IDistributedCache>      _cache;
    private readonly Mock<IUserRepository>        _users;
    private readonly Mock<IEntraIdTokenService>   _tokenService;
    private readonly OAuthController              _controller;

    private const string ClientId    = "test-client-id";
    private const string RedirectUri = "https://app.example.com/callback";

    public OAuthControllerTests()
    {
        _cache        = new Mock<IDistributedCache>();
        _users        = new Mock<IUserRepository>();
        _tokenService = new Mock<IEntraIdTokenService>();

        _tokenService
            .Setup(ts => ts.GenerateToken(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Claim[]>()))
            .Returns("mock-jwt-token");

        _cache
            .Setup(c => c.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _cache
            .Setup(c => c.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _controller = new OAuthController(
            _cache.Object, _users.Object, _tokenService.Object,
            NullLogger<OAuthController>.Instance,
            ResiliencePipeline.Empty)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
    }

    // ── /oauth/authorize GET ──────────────────────────────────────────────── //

    [Fact]
    public void Authorize_UnsupportedResponseType_ReturnsBadRequest()
    {
        var result = _controller.Authorize("token", ClientId, RedirectUri);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("unsupported_response_type", JsonSerializer.Serialize(bad.Value));
    }

    [Fact]
    public void Authorize_MissingClientId_ReturnsBadRequest()
    {
        var result = _controller.Authorize("code", "", RedirectUri);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public void Authorize_ValidRequest_ReturnsHtmlLoginForm()
    {
        var result = _controller.Authorize("code", ClientId, RedirectUri);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal("text/html", content.ContentType);
        Assert.Contains("api_key", content.Content);
    }

    // ── /oauth/authorize POST ─────────────────────────────────────────────── //

    [Fact]
    public async Task AuthorizePost_InvalidKeyFormat_ReturnsHtmlWithError()
    {
        var result = await _controller.AuthorizePost(
            "not-a-guid", ClientId, RedirectUri);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Contains("Invalid API key format", content.Content);
    }

    [Fact]
    public async Task AuthorizePost_KeyNotFound_ReturnsHtmlWithError()
    {
        _users.Setup(u => u.FindByApiKeyAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync((UserLookupResult?)null);

        var result = await _controller.AuthorizePost(
            Guid.NewGuid().ToString(), ClientId, RedirectUri);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Contains("API key not recognised", content.Content);
    }

    [Fact]
    public async Task AuthorizePost_ValidKey_StoresCodeAndReturnsRedirectHtml()
    {
        _users.Setup(u => u.FindByApiKeyAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(new UserLookupResult(42, 2));

        var result = await _controller.AuthorizePost(
            Guid.NewGuid().ToString(), ClientId, RedirectUri, state: "csrf-state");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal("text/html", content.ContentType);
        Assert.Contains(RedirectUri, content.Content);

        _cache.Verify(c => c.SetAsync(
            It.Is<string>(k => k.StartsWith("oauth_code:")),
            It.IsAny<byte[]>(),
            It.IsAny<DistributedCacheEntryOptions>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── /oauth/token ──────────────────────────────────────────────────────── //

    [Fact]
    public async Task Token_UnsupportedGrantType_ReturnsBadRequest()
    {
        var result = await _controller.Token("implicit", "code", "verifier", ClientId, RedirectUri);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("unsupported_grant_type", JsonSerializer.Serialize(bad.Value));
    }

    [Fact]
    public async Task Token_CodeNotFoundInCache_ReturnsBadRequest()
    {
        _cache.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync((byte[]?)null);

        var result = await _controller.Token(
            "authorization_code", "missing-code", "verifier", ClientId, RedirectUri);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("invalid_grant", JsonSerializer.Serialize(bad.Value));
    }

    [Fact]
    public async Task Token_ClientIdMismatch_ReturnsBadRequest()
    {
        SetupCacheEntry(clientId: "different-client");

        var result = await _controller.Token(
            "authorization_code", "valid-code", "verifier", ClientId, RedirectUri);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("invalid_grant", JsonSerializer.Serialize(bad.Value));
    }

    [Fact]
    public async Task Token_PkceVerificationFailed_ReturnsBadRequest()
    {
        var (_, challenge) = MakePkce();
        SetupCacheEntry(codeChallenge: challenge);

        var result = await _controller.Token(
            "authorization_code", "valid-code", "wrong-verifier", ClientId, RedirectUri);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("invalid_grant", JsonSerializer.Serialize(bad.Value));
    }

    [Fact]
    public async Task Token_ValidRequest_NoPkce_ReturnsAccessToken()
    {
        SetupCacheEntry(codeChallenge: null);

        var result = await _controller.Token(
            "authorization_code", "valid-code", "", ClientId, RedirectUri);

        var ok = Assert.IsType<OkObjectResult>(result);
        var json = JsonSerializer.Serialize(ok.Value);
        Assert.Contains("mock-jwt-token", json);
        Assert.Contains("Bearer", json);
    }

    [Fact]
    public async Task Token_ValidRequest_WithPkce_ReturnsAccessToken()
    {
        var (verifier, challenge) = MakePkce();
        SetupCacheEntry(codeChallenge: challenge);

        var result = await _controller.Token(
            "authorization_code", "valid-code", verifier, ClientId, RedirectUri);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Contains("mock-jwt-token", JsonSerializer.Serialize(ok.Value));
    }

    // ── /oauth/register ───────────────────────────────────────────────────── //

    [Fact]
    public async Task Register_NoRedirectUris_ReturnsBadRequest()
    {
        var result = await _controller.Register(
            new OAuthController.ClientRegistrationRequest(null, "My App"));

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Register_ValidRequest_StoresClientAndReturnsClientId()
    {
        var result = await _controller.Register(
            new OAuthController.ClientRegistrationRequest(
                new[] { RedirectUri }, "My App"));

        var ok = Assert.IsType<OkObjectResult>(result);
        var json = JsonSerializer.Serialize(ok.Value);
        Assert.Contains("client_id", json);
        Assert.Contains(RedirectUri, json);

        _cache.Verify(c => c.SetAsync(
            It.Is<string>(k => k.StartsWith("oauth_client:")),
            It.IsAny<byte[]>(),
            It.IsAny<DistributedCacheEntryOptions>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Helpers ───────────────────────────────────────────────────────────── //

    private void SetupCacheEntry(
        string? codeChallenge = null,
        string  clientId      = ClientId,
        string  redirectUri   = RedirectUri)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            UserId              = 42,
            CompanyId           = 2,
            ClientId            = clientId,
            RedirectUri         = redirectUri,
            CodeChallenge       = codeChallenge,
            CodeChallengeMethod = "S256",
            Resource            = (string?)null,
        });

        _cache.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(bytes);
    }

    private static (string Verifier, string Challenge) MakePkce()
    {
        // RFC 7636 Appendix B test vector
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }
}
