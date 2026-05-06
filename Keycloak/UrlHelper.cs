namespace Keycloak;

internal static class UrlHelper
{
    public static bool IsLocalUrl(string? url)
    {
        if (string.IsNullOrEmpty(url))
            return false;

        return url[0] == '/' && !url.StartsWith("//") && !url.StartsWith("/\\");
    }
}