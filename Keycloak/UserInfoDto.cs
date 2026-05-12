namespace Keycloak;

public sealed record UserInfoDto(
    Guid UserId,
    string Email,
    bool EmailVerified,
    string Username,
    string DisplayName,
    string GivenName,
    string FamilyName,
    IReadOnlyCollection<string> Roles,
    DateTimeOffset? SessionExpiresAt = null);