using System.Security.Claims;

namespace Keycloak;

public static class ClaimsPrincipalExtensions
{
    public static UserInfoDto ToUserInfoDto(this ClaimsPrincipal user, DateTimeOffset? sessionExpiresAt = null)
    {
        var identity = (ClaimsIdentity)user.Identity!;

        return new UserInfoDto(
            UserId: Guid.Parse(user.FindFirstValue("sub")!),
            Email: user.FindFirstValue("email") ?? "",
            EmailVerified: bool.TryParse(user.FindFirstValue("email_verified"), out var v) && v,
            Username: user.FindFirstValue("preferred_username") ?? "",
            DisplayName: user.FindFirstValue("name") ?? "",
            GivenName: user.FindFirstValue("given_name") ?? "",
            FamilyName: user.FindFirstValue("family_name") ?? "",
            Roles: user.FindAll(identity.RoleClaimType).Select(c => c.Value).ToArray(),
            SessionExpiresAt: sessionExpiresAt);
    }
}