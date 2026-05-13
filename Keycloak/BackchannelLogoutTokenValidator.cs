using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace Keycloak;

/// <summary>
/// Walidator logout tokenu zgodnie z OIDC Back-Channel Logout 1.0 §2.4.
/// Używa JWKS pobranego przez ConfigurationManagera handlera OIDC (cache wspólny z normalnym flow logowania).
/// Replay protection przez Redis: jti zapisywany na okres dopuszczalnego skew, drugie wystąpienie -> błąd.
/// </summary>
internal sealed class BackchannelLogoutTokenValidator(
    IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor,
    IDistributedCache cache)
{
    private const string LogoutEventType = "http://schemas.openid.net/event/backchannel-logout";
    private const string JtiCachePrefix = "bcl-jti:";
    private static readonly TimeSpan MaxIatAge = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ReplayWindow = TimeSpan.FromMinutes(5);

    public sealed record Result(bool IsValid, string? Sub, string? Jti, string? ErrorCode, string? ErrorDescription)
    {
        public static Result Ok(string sub, string jti) => new(true, sub, jti, null, null);
        public static Result Fail(string code, string description) => new(false, null, null, code, description);
    }

    public async Task<Result> ValidateAsync(string logoutToken, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(logoutToken))
            return Result.Fail("invalid_request", "Brak logout_token.");

        var oidcOpts = oidcOptionsMonitor.Get(OpenIdConnectDefaults.AuthenticationScheme);
        var config = await oidcOpts.ConfigurationManager!.GetConfigurationAsync(ct);

        var tvp = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = config.Issuer,
            ValidateAudience = true,
            ValidAudience = oidcOpts.ClientId,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = config.SigningKeys,
            // Logout token nie musi mieć exp — własne sprawdzenie iat poniżej.
            ValidateLifetime = false,
            NameClaimType = "sub",
        };

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(logoutToken, tvp);
        if (!result.IsValid)
            return Result.Fail("invalid_token", result.Exception?.Message ?? "Walidacja podpisu nie powiodła się.");

        var jwt = (JsonWebToken)result.SecurityToken;

        // iat — wymagane, świeże.
        if (!jwt.TryGetPayloadValue<long>("iat", out var iatUnix))
            return Result.Fail("invalid_token", "Brak claim 'iat'.");
        var iat = DateTimeOffset.FromUnixTimeSeconds(iatUnix);
        if (DateTimeOffset.UtcNow - iat > MaxIatAge)
            return Result.Fail("invalid_token", "Token zbyt stary (iat poza tolerancją skew).");

        // nonce MUST NOT być obecny.
        if (jwt.TryGetPayloadValue<string>("nonce", out _))
            return Result.Fail("invalid_token", "Logout token nie może zawierać claim 'nonce'.");

        // events.{LogoutEventType} musi istnieć.
        if (!jwt.TryGetPayloadValue<JsonElement>("events", out var events)
            || events.ValueKind != JsonValueKind.Object
            || !events.TryGetProperty(LogoutEventType, out _))
        {
            return Result.Fail("invalid_token", $"Brak wymaganego event '{LogoutEventType}' w claim 'events'.");
        }

        // jti — wymagane do replay protection.
        if (!jwt.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrEmpty(jti))
            return Result.Fail("invalid_token", "Brak claim 'jti'.");

        // sub — w tym BFF wylogowujemy po sub. sid ignorujemy świadomie (wyloguj ze wszystkich urządzeń).
        if (!jwt.TryGetPayloadValue<string>("sub", out var sub) || string.IsNullOrEmpty(sub))
            return Result.Fail("invalid_token", "Brak claim 'sub'.");

        // Replay protection: jeśli jti już widziany w oknie -> odrzuć.
        var jtiKey = JtiCachePrefix + jti;
        if (await cache.GetAsync(jtiKey, ct) is not null)
            return Result.Fail("token_replayed", "Logout token już użyty.");

        await cache.SetAsync(jtiKey, [1], new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ReplayWindow
        }, ct);

        return Result.Ok(sub, jti);
    }
}
