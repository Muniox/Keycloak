# Security

## Model bezpieczeństwa

Aplikacja używa podejścia **BFF / server-side session**:

- przeglądarka dostaje tylko cookie sesyjne,
- tokeny OIDC są trzymane po stronie serwera,
- sesja jest przechowywana w Redisie przez `ITicketStore`,
- `access_token` jest odnawiany automatycznie przez `refresh_token`,
- czas życia lokalnej sesji jest powiązany z lifetime `refresh_token` z Keycloaka.

To jest poprawne i produkcyjne podejście, ale wymaga kilku świadomych decyzji operacyjnych.

## Redis i sesje

Redis przechowuje tickety uwierzytelniające. Tickety są szyfrowane przez ASP.NET Core Data Protection przed zapisem.

To oznacza, że:

- sam odczyt danych sesyjnych z Redisa nie daje od razu jawnych tokenów,
- bezpieczeństwo tych danych zależy także od bezpieczeństwa kluczy Data Protection.

## Data Protection key ring

Klucze Data Protection **nie powinny być trzymane w `appsettings.json`**.

Aplikacja generuje je sama. Należy tylko skonfigurować trwałe miejsce ich przechowywania.

Jeżeli key ring nie jest trwały i współdzielony:

- restart aplikacji może unieważnić istniejące sesje,
- wiele instancji aplikacji może nie umieć odszyfrować tych samych ticketów,
- użytkownicy mogą być losowo wylogowywani po deployu lub restarcie.

## Czy trzymać key ring w Redisie?

Jeżeli Redis jest wymagany do działania aplikacji, trzymanie key ringa w Redisie jest wygodne i operacyjnie sensowne.

Jednocześnie trzeba znać trade-off:

- jeżeli ktoś uzyska dostęp do Redisa z sesjami,
- i w tym samym Redisie znajduje się także key ring,
- to kompromitacja Redisa może umożliwić odszyfrowanie danych sesyjnych.

Innymi słowy:

- **Redis na sesje** — tak,
- **Redis na key ring** — możliwe,
- **najbezpieczniej**: sesje w Redisie, a key ring w osobnym storage.

## Rekomendacja

Najbezpieczniejszy wariant:

- sesje w Redisie,
- key ring poza Redisem,
- np. współdzielony filesystem, Azure Blob Storage, baza danych lub inny dedykowany storage,
- opcjonalnie dodatkowa ochrona kluczy at rest.

Wariant kompromisowy:

- key ring w Redisie,
- ale tylko jeśli Redis ma włączoną persystencję,
- jest odpowiednio zabezpieczony sieciowo,
- i akceptowany jest trade-off polegający na tym, że kompromitacja Redisa oznacza bardzo duży wpływ bezpieczeństwa.

## Dodatkowe wymagania produkcyjne

Aby rozwiązanie było w pełni production-ready, należy dopiąć także:

- ochronę **CSRF / antiforgery** dla endpointów typu `POST`,
- **backchannel logout**,
- reakcję na unieważnienie sesji po stronie Keycloaka,
- trwałą persystencję i współdzielenie kluczy Data Protection,
- sensowne logowanie i observability,
- odpowiednie zabezpieczenie samego Redisa.
