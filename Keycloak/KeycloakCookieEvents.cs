using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Keycloak;

/// <summary>
/// Cookie auth eventy dla Keycloak BFF.
/// Odpalają się przy każdym żądaniu z ważnym ciasteczkiem sesyjnym —
/// transparentnie odświeżają wygasły access_token przez refresh_token.
/// </summary>
internal static class KeycloakCookieEvents
{
    // Margines clock skew / latency — refresh odpala się 30s PRZED rzeczywistym wygaśnięciem,
    // żeby pierwsze żądanie po wygaśnięciu nie złapało 401 z resource serverów.
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Sprawdza czy access_token wygasł i jeśli tak — odświeża go przez refresh_token.
    /// Zachowuje oryginalny id_token (Keycloak nie zwraca nowego przy refreshu, a jest potrzebny do logout).
    /// Aktualizuje <see cref="AuthenticationProperties.ExpiresUtc"/> z nowym <c>refresh_expires_in</c>.
    /// Przy porażce refresha — odrzuca sesję (user musi się zalogować ponownie).
    /// </summary>
    internal static async Task OnValidatePrincipal(CookieValidatePrincipalContext ctx)
    {
        var expiresAt = ctx.Properties.GetTokenValue("expires_at");
        if (expiresAt is null)
            return; // sesja bez tokenów (nie powinno się zdarzyć w naszym flow)

        var expiresAtDate = DateTimeOffset.Parse(expiresAt, CultureInfo.InvariantCulture);

        // Access_token jeszcze ważny — nic nie rób, 99% żądań kończy tutaj.
        if (DateTimeOffset.UtcNow < expiresAtDate - RefreshMargin)
            return;

        var refreshToken = ctx.Properties.GetTokenValue("refresh_token");
        if (refreshToken is null)
        {
            // Brak refresh_tokena = nie ma jak odnowić.
            ctx.RejectPrincipal();
            return;
        }

        var services = ctx.HttpContext.RequestServices;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Keycloak.CookieEvents");
        var tokenClient = services.GetRequiredService<KeycloakTokenClient>();

        TokenResponse? tokens;
        try
        {
            tokens = await tokenClient.RefreshAsync(refreshToken, ctx.HttpContext.RequestAborted);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Token refresh threw — rejecting session");
            ctx.RejectPrincipal();
            return;
        }

        if (tokens is null)
        {
            // Keycloak odrzucił refresh — najczęściej refresh_token wygasł lub został revoked.
            logger.LogInformation("Token refresh rejected by Keycloak — rejecting session");
            ctx.RejectPrincipal();
            return;
        }

        // Zachowaj oryginalny id_token — Keycloak nie zwraca go przy refreshu,
        // a jest wymagany do RP-Initiated Logout (id_token_hint).
        var idToken = ctx.Properties.GetTokenValue("id_token");

        var newTokens = new List<AuthenticationToken>
        {
            new() { Name = "access_token",  Value = tokens.AccessToken },
            new() { Name = "refresh_token", Value = tokens.RefreshToken },
            new() { Name = "expires_at",    Value = DateTimeOffset.UtcNow
                                                        .AddSeconds(tokens.ExpiresIn)
                                                        .ToString("o", CultureInfo.InvariantCulture) },
        };

        if (idToken is not null)
            newTokens.Add(new AuthenticationToken { Name = "id_token", Value = idToken });

        ctx.Properties.StoreTokens(newTokens);

        // Podbij ExpiresUtc cookie na nowy lifetime refresh_tokena.
        if (tokens.RefreshExpiresIn > 0)
            ctx.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(tokens.RefreshExpiresIn);

        // ShouldRenew = true → ASP.NET wywoła ITicketStore.RenewAsync z zaktualizowanym ticketem.
        ctx.ShouldRenew = true;

        logger.LogDebug("Access token refreshed successfully");
    }
}
