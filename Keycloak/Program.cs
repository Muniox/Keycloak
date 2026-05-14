using Keycloak;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using StackExchange.Redis;
using System.Security.Claims;
using System.Text.Json;


var builder = WebApplication.CreateBuilder(args);

// Apka stoi za nginx proxy manager — czytamy X-Forwarded-* żeby Request.Scheme=https
// i cookie Secure działały. Pusta lista zaufanych = middleware IGNORUJE nagłówki,
// więc dodajemy pulę sieci docker (RFC 1918). Apka nie ma `ports:` w compose,
// więc realnie dosięgnie ją tylko ruch z tej puli.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedProto |
        ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("172.16.0.0/12"));
});

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services
    .AddOptionsWithValidateOnStart<KeycloakAuthOptions>()
    .BindConfiguration(KeycloakAuthOptions.SectionName)
    .ValidateDataAnnotations()
    .Validate(opt => UrlHelper.IsLocalUrl(opt.PostLogoutRedirectUri),
       $"{KeycloakAuthOptions.SectionName}:{nameof(KeycloakAuthOptions.PostLogoutRedirectUri)} musi zaczynać się od '/'.")
    .Validate(opt => System.Text.RegularExpressions.Regex.IsMatch(opt.SessionKeyNamespace, "^[a-z0-9][a-z0-9-]*$"), 
        $"{KeycloakAuthOptions.SectionName}: {nameof(KeycloakAuthOptions.SessionKeyNamespace)} " +
        $"musi być lowercase, alfanumeryczne, opcjonalnie z myślnikami.");

// ── Redis ────────────────────────────────────────────────────
builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    var opts = sp.GetRequiredService<IOptions<KeycloakAuthOptions>>().Value;
    return ConnectionMultiplexer.Connect(opts.RedisConnectionString);
});

builder.Services.AddStackExchangeRedisCache(_ => { });

builder.Services
    .AddOptions<RedisCacheOptions>()
    .Configure<IServiceProvider>((options, sp) =>
    {
        var keycloak = sp.GetRequiredService<IOptions<KeycloakAuthOptions>>().Value;

        // IDistributedCache traktuje InstanceName jako dosłowny prefix — bez separatora.
        // Dlatego dorzucamy ":" tutaj, a walidacja SessionKeyNamespace zakazuje go w konfigu.
        options.InstanceName = keycloak.SessionKeyNamespace + ":";
        options.ConnectionMultiplexerFactory = () =>
            Task.FromResult(sp.GetRequiredService<IConnectionMultiplexer>());
    });

builder.Services.AddSingleton<RedisTicketStore>();
builder.Services.AddSingleton<ITicketStore>(sp => sp.GetRequiredService<RedisTicketStore>());

builder.Services.AddSingleton<BackchannelLogoutTokenValidator>();

builder.Services.AddHttpClient<KeycloakTokenClient>();

// ── Authentication ───────────────────────────────────────────
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
        options.SlidingExpiration = false;
        options.Events.OnValidatePrincipal = KeycloakCookieEvents.OnValidatePrincipal;
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
        // Ustaw ExpiresUtc cookie na lifetime refresh_tokena z Keycloaka.
        options.Events.OnTokenResponseReceived = ctx =>
        {
            var refreshExpiresIn = ctx.TokenEndpointResponse?.GetParameter("refresh_expires_in");
            if (int.TryParse(refreshExpiresIn, out var seconds) && seconds > 0)
            {
                ctx.Properties!.ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(seconds);
            }
            return Task.CompletedTask;
        };
        // Ekstrakcja ról
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

// ── Options binding dla auth handlers ────────────────────────
builder.Services
    .AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .Configure<IOptions<KeycloakAuthOptions>, ITicketStore>((options, keycloakOptions, ticketStore) =>
    {
        var keycloak = keycloakOptions.Value;

        options.Cookie.Name = keycloak.CookieName;
        options.SessionStore = ticketStore;
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

app.UseForwardedHeaders();
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

// OIDC Back-Channel Logout 1.0 — Keycloak woła ten endpoint przy unieważnieniu sesji po stronie IdP.
// Wylogowuje usera ze wszystkich urządzeń w obrębie tej aplikacji (po sub). sid świadomie ignorujemy.
app.MapPost("/auth/backchannel-logout", async (
    HttpRequest request,
    HttpResponse response,
    BackchannelLogoutTokenValidator validator,
    RedisTicketStore ticketStore,
    ILoggerFactory loggerFactory,
    CancellationToken ct) =>
{
    var logger = loggerFactory.CreateLogger("BackchannelLogout");
    response.Headers.CacheControl = "no-store";

    if (!request.HasFormContentType)
        return Results.BadRequest(new { error = "invalid_request", error_description = "Wymagany Content-Type application/x-www-form-urlencoded." });

    var form = await request.ReadFormAsync(ct);
    var logoutToken = form["logout_token"].ToString();

    var result = await validator.ValidateAsync(logoutToken, ct);
    if (!result.IsValid)
    {
        logger.LogWarning("Backchannel logout odrzucony: {Code} {Description}", result.ErrorCode, result.ErrorDescription);
        return Results.BadRequest(new { error = result.ErrorCode, error_description = result.ErrorDescription });
    }

    var removed = await ticketStore.RemoveAllUserSessionsAsync(result.Sub!);
    logger.LogInformation("Backchannel logout: sub={Sub} jti={Jti} usunięto sesji={Count}", result.Sub, result.Jti, removed);

    return Results.Ok();
});

app.Run();
