using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace Keycloak;

/// <summary>
/// Typed HTTP client do komunikacji z Keycloak token endpointem.
/// Wstrzykiwany przez <see cref="IHttpClientFactory"/> (rejestracja w <c>Program.cs</c>
/// przez <c>AddHttpClient&lt;KeycloakTokenClient&gt;</c>).
/// </summary>
internal sealed class KeycloakTokenClient(
    HttpClient http,
    IOptions<KeycloakAuthOptions> options)
{
    private readonly KeycloakAuthOptions _opts = options.Value;

    /// <summary>
    /// Wymienia refresh_token na nowy zestaw tokenów.
    /// Zwraca <c>null</c> gdy refresh padnie (refresh_token wygasł, został revoked,
    /// błąd sieci) — caller traktuje to jako sygnał do <c>RejectPrincipal</c>.
    /// </summary>
    public async Task<TokenResponse?> RefreshAsync(string refreshToken, CancellationToken ct = default)
    {
        var tokenUrl = $"{_opts.Authority.TrimEnd('/')}/protocol/openid-connect/token";

        // Keycloak token endpoint wymaga application/x-www-form-urlencoded, nie JSON.
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"]    = "refresh_token",
            ["client_id"]     = _opts.ClientId,
            ["client_secret"] = _opts.ClientSecret,
            ["refresh_token"] = refreshToken,
        });

        using var response = await http.PostAsync(tokenUrl, content, ct);
        if (!response.IsSuccessStatusCode)
            return null;

        return await response.Content.ReadFromJsonAsync<TokenResponse>(ct);
    }
}

/// <summary>
/// Odpowiedź Keycloaka z endpointu <c>/protocol/openid-connect/token</c>.
/// <c>id_token</c> nie jest zwracany przy refresh — trzeba zachować poprzedni.
/// </summary>
internal sealed record TokenResponse(
    [property: JsonPropertyName("access_token")]       string AccessToken,
    [property: JsonPropertyName("refresh_token")]      string RefreshToken,
    [property: JsonPropertyName("expires_in")]         int ExpiresIn,
    [property: JsonPropertyName("refresh_expires_in")] int RefreshExpiresIn);
