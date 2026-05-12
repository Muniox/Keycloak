using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Keycloak;

/// <summary>
/// Implementacja <see cref="ITicketStore"/> przechowująca tickety uwierzytelniające w Redis.
/// Tickety są szyfrowane przez <see cref="IDataProtector"/> przed zapisem — surowy dostęp
/// do Redisa nie ujawnia tokenów ani claims.
/// Dodatkowo utrzymuje indeks sesji per użytkownik (Redis SET <c>{InstanceName}{{sub}}:user-sessions</c>),
/// co umożliwia wylistowanie lub unieważnienie wszystkich sesji danego użytkownika.
/// </summary>
internal sealed class RedisTicketStore(
    IDistributedCache cache,
    IConnectionMultiplexer redis,
    IOptions<RedisCacheOptions> cacheOptions,
    IDataProtectionProvider protectionProvider
    ) : ITicketStore
{
    private const string UserSessionsKeySuffix = "user-sessions";

    // Fallback gdy ticket nie ma ExpiresUtc — defensywnie, żeby nic nie wisiało w Redisie wiecznie.
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromHours(1);

    // InstanceName jest doklejany automatycznie przez IDistributedCache do operacji Get/Set/Remove.
    // Dla operacji bezpośrednich przez IConnectionMultiplexer (SET indeksu) musimy go dokleić ręcznie.
    private readonly string _prefix = cacheOptions.Value.InstanceName ?? string.Empty;

    // Purpose ".v1" pozwala w przyszłości zmienić format zapisu — wystarczy podbić wersję,
    // a stare sesje zaszyfrowane ".v1" przestaną się odszyfrowywać i userzy zalogują się ponownie.
    private readonly IDataProtector _protector = protectionProvider.CreateProtector("Keycloak.RedisTicketStore.v1");

    private string BuildIndexKey(string sub) => $"{_prefix}{{{sub}}}:{UserSessionsKeySuffix}";

    /// <summary>Tworzy nową sesję — generuje GUID, zapisuje ticket, dodaje do indeksu użytkownika.</summary>
    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var sub = ticket.Principal?.FindFirst("sub")?.Value
            ?? throw new InvalidOperationException(
            "Ticket nie zawiera claim 'sub' - wymagany do hash tagu w kluczu sesji.");

        var sessionKey = $"{{{sub}}}.{Guid.NewGuid():N}";
        await WriteAsync(sessionKey, ticket);
        await AddToUserIndexAsync(sessionKey, ticket);
        return sessionKey;
    }

    /// <summary>Odnawia istniejącą sesję — nadpisuje ticket i odświeża TTL indeksu.</summary>
    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        await WriteAsync(key, ticket);
        await AddToUserIndexAsync(key, ticket);
    }

    /// <summary>Usuwa pojedynczą sesję wraz z wpisem w indeksie użytkownika.</summary>
    public async Task RemoveAsync(string key)
    {
        var sub = ExtractSubFromKey(key);

        // Brak sub = ticket anonimowy albo nie udało się odszyfrować.
        // W obu przypadkach nic do sprzątnięcia w indeksie — zostaje samo usunięcie ticketu.
        if (sub is null)
        {
            await cache.RemoveAsync(key);
            return;
        }

        // SREM z indeksu i DEL ticketu są niezależne — wykonujemy równolegle w jednym RTT.
        var db = redis.GetDatabase();
        await Task.WhenAll(
            db.SetRemoveAsync(BuildIndexKey(sub), key),
            cache.RemoveAsync(key));
    }

    /// <summary>Pobiera ticket z Redis. Zwraca <c>null</c> gdy sesja wygasła,
    /// nie istnieje lub payload jest niewłaściwy (np. po rotacji kluczy szyfrujących).</summary>
    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var encrypted = await cache.GetAsync(key);
        if (encrypted is null)
            return null;

        try
        {
            var plaintextInBytes = _protector.Unprotect(encrypted);
            return TicketSerializer.Default.Deserialize(plaintextInBytes);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Klucz szyfrujący zniknął (rotacja, restart bez persystencji keyringu) lub payload jest skorumpowany.
            // Zwracamy null — ASP.NET potraktuje to jak brak sesji i wymusi ponowny login.
            return null;
        }
    }

    /// <summary>Usuwa wszystkie sesje użytkownika identyfikowanego przez <paramref name="sub"/>.
    /// Zwraca liczbę usuniętych sesji.</summary>
    public async Task<int> RemoveAllUserSessionsAsync(string sub)
    {
        var db = redis.GetDatabase();
        var indexKey = BuildIndexKey(sub);
        var sessionIds = await db.SetMembersAsync(indexKey);

        // Batch DEL: 1 round-trip dla N sesji + indeks.
        // Działa zarówno na single-node jak i Redis Cluster — wszystkie klucze
        // mają wspólny hash tag {sub}, więc lądują w tym samym slocie.
        var keysToDelete = sessionIds
            .Select(id => (RedisKey)(_prefix + (string)id!))
            .Append((RedisKey)indexKey)
            .ToArray();

        await db.KeyDeleteAsync(keysToDelete);
        return sessionIds.Length;
    }

    /// <summary>Dodaje klucz sesji do Redis SET indeksowanego po <c>sub</c>.
    /// TTL indeksu jest podbijane do najdłuższego TTL spośród aktywnych sesji —
    /// inaczej indeks mógłby wygasnąć przed ostatnią sesją usera.</summary>
    private async Task AddToUserIndexAsync(string sessionKey, AuthenticationTicket ticket)
    {
        var sub = ticket.Principal?.FindFirst("sub")?.Value;
        if (sub is null) return;

        var db = redis.GetDatabase();
        var indexKey = BuildIndexKey(sub);
        await db.SetAddAsync(indexKey, sessionKey);

        // Podbij TTL tylko gdy nowa sesja żyje dłużej niż obecny TTL indeksu —
        // dzięki temu indeks zawsze przetrwa najdłużej żyjącą sesję.
        var ttl = GetTtl(ticket);
        var currentTtl = await db.KeyTimeToLiveAsync(indexKey);
        if (currentTtl is null || ttl > currentTtl)
            await db.KeyExpireAsync(indexKey, ttl);
    }

    private async Task WriteAsync(string key, AuthenticationTicket ticket)
    {
        // Kolejność: Serialize → Protect. Najpierw zamieniamy ticket na binarkę przez wbudowany
        // TicketSerializer (rozumie claims i AuthenticationProperties z tokenami), potem szyfrujemy.
        var serialized = TicketSerializer.Default.Serialize(ticket);
        var encrypted = _protector.Protect(serialized);

        await cache.SetAsync(key, encrypted, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = GetTtl(ticket)
        });
    }

    private static string? ExtractSubFromKey(string sessionKey)
    {
        // Format klucza: "{sub}.guid" — sub siedzi między klamerkami na początku.
        if (!sessionKey.StartsWith('{'))
            return null;

        var closingBrace = sessionKey.IndexOf('}');
        if (closingBrace < 0)
            return null;

        return sessionKey[1..closingBrace];
    }

    private static TimeSpan GetTtl(AuthenticationTicket ticket)
    {
        if (ticket.Properties.ExpiresUtc.HasValue)
        {
            var ttl = ticket.Properties.ExpiresUtc.Value - DateTimeOffset.UtcNow;
            if (ttl > TimeSpan.Zero)
                return ttl;
        }
        return DefaultTtl;
    }
}
