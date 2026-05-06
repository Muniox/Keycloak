using System.ComponentModel.DataAnnotations;

namespace Keycloak;

/// <summary>
/// Opcje konfiguracyjne biblioteki Keycloak BFF.
/// Bindowane z sekcji <c>KeycloakAuth</c> w <c>appsettings.json</c>.
/// Właściwości oznaczone <see cref="RequiredAttribute"/> są walidowane przy starcie aplikacji —
/// brak którejkolwiek powoduje wyjątek zamiast cichego błędu w runtime.
/// </summary>
public class KeycloakAuthOptions
{
    public const string SectionName = "KeycloakAuth";

    // ── OIDC ────────────────────────────────────────────────

    /// <summary>Adres realm Keycloak, np. <c>https://keycloak.example.com/realms/my-realm</c>.</summary>
    [Required] public string Authority { get; set; } = "";

    /// <summary>Identyfikator klienta OIDC zarejestrowanego w Keycloak Admin Console.</summary>
    [Required] public string ClientId { get; set; } = "";

    /// <summary>Secret klienta OIDC (zakładka Credentials w Keycloak Admin Console).</summary>
    [Required] public string ClientSecret { get; set; } = "";

    // ── Cookie ──────────────────────────────────────────────

    /// <summary>Nazwa ciasteczka sesyjnego. Domyślnie <c>__Host-session</c> (prefix <c>__Host-</c> wymusza Secure + brak Domain).</summary>
    public string CookieName { get; set; } = "__Host-session";

    /// <summary>
    /// Lokalna ścieżka, na którą trafia użytkownik po pełnym wylogowaniu
    /// (po powrocie z Keycloak przez <c>/signout-callback-oidc</c>). Musi zaczynać się od <c>/</c>.
    /// Domyślnie <c>/</c>.
    /// </summary>
    public string PostLogoutRedirectUri { get; set; } = "/";
}
