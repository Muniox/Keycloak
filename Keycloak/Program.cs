using System.Security.Claims;
using System.Text.Json;
using Keycloak;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services
    .AddOptionsWithValidateOnStart<KeycloakAuthOptions>()
    .BindConfiguration(KeycloakAuthOptions.SectionName)
    .ValidateDataAnnotations()
    .Validate(o => UrlHelper.IsLocalUrl(o.PostLogoutRedirectUri),
        $"{KeycloakAuthOptions.SectionName}:{nameof(KeycloakAuthOptions.PostLogoutRedirectUri)} musi zaczynać się od '/'.");

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
        options.Events.OnRedirectToLogin = ctx =>
        {
            // BFF pattern: always return 401 instead of 302 redirect.
            // The SPA frontend detects 401 and navigates to /auth/login when needed.
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    })
    .AddOpenIdConnect(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.MapInboundClaims = false;
        options.Events.OnTokenValidated = ctx =>
        {
            if (ctx.Principal?.Identity is not ClaimsIdentity identity)
                return Task.CompletedTask;

            var resourceAccess = identity.FindFirst("resource_access")?.Value;
            if (string.IsNullOrEmpty(resourceAccess))
                return Task.CompletedTask;

            var clientId = ctx.Options.ClientId!;
            using var doc = JsonDocument.Parse(resourceAccess);

            if (!doc.RootElement.TryGetProperty(clientId, out var client))
                return Task.CompletedTask;

            if (!client.TryGetProperty("roles", out var roles) || roles.ValueKind != JsonValueKind.Array)
                return Task.CompletedTask;

            foreach (var role in roles.EnumerateArray())
            {
                var name = role.GetString();
                if (!string.IsNullOrEmpty(name))
                    identity.AddClaim(new Claim(identity.RoleClaimType, name));
            }

            return Task.CompletedTask;
        };

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");

        options.TokenValidationParameters.NameClaimType = "preferred_username";
        options.TokenValidationParameters.RoleClaimType = "roles";
    });

builder.Services
    .AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .Configure<IOptions<KeycloakAuthOptions>>((options, keycloakOptions) =>
    {
        var keycloak = keycloakOptions.Value;

        options.Cookie.Name = keycloak.CookieName;
    });

builder.Services
    .AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
    .Configure<IOptions<KeycloakAuthOptions>>((options, keycloakOptions) =>
    {
        var keycloak = keycloakOptions.Value;

        options.Authority = keycloak.Authority;
        options.ClientId = keycloak.ClientId;
        options.ClientSecret = keycloak.ClientSecret;
        options.SignedOutRedirectUri = keycloak.PostLogoutRedirectUri;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/auth/users/me", (ClaimsPrincipal user) => Results.Ok(user.ToUserInfoDto()))
    .RequireAuthorization()
    .Produces<UserInfoDto>();

app.MapGet("/auth/login", (string? returnUrl, ClaimsPrincipal user) =>
{
    var safeUrl = UrlHelper.IsLocalUrl(returnUrl) ? returnUrl! : "/";

    if (user.Identity?.IsAuthenticated == true)
        return Results.LocalRedirect(safeUrl);

    return Results.Challenge(
        new AuthenticationProperties { RedirectUri = safeUrl },
        [OpenIdConnectDefaults.AuthenticationScheme]);
});

app.MapPost("/auth/logout", (ClaimsPrincipal user, IOptions<KeycloakAuthOptions> opts) =>
{
    if (user.Identity?.IsAuthenticated != true)
        return Results.LocalRedirect(opts.Value.PostLogoutRedirectUri);

    return Results.SignOut(authenticationSchemes:
    [
        CookieAuthenticationDefaults.AuthenticationScheme,
        OpenIdConnectDefaults.AuthenticationScheme
    ]);
});

app.Run();
