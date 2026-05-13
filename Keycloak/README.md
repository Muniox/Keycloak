Keycloak

co jest zawarte:

- BFF patern
- cookie auth dla clienta, SameSite=Strict, Secure, 401/403 zamiast redirectów (redirecty są z MVC a my musieliśmy zmienić na BFF patern)
- OIDC Authorization Code + PKCE
- Zapisywanie tokenów poprzez SaveTokens
- MapInboundClaims=false aby nie modyfikować odpowiedzi keycloaka
- Mapowanie ról z resource_access[clientId].roles na ClaimsIdentity.RoleClaimType (należy włączyć w keycloak)
- Redis jako ITicketStore (server-side session store) + RedisTicketStore
- Walidacja konfiguracji przy starcie (AddOptionsWithValidateOnStart + DataAnnotations)
- Endpointy które wystawia backend dla clienta /auth/login, /auth/logout, /auth/users/me, /auth/backchannel-logout
- Helper zapewniający ochorenę przed redirect
- Refresh Tokena w OnValidatePrincipal (Cookie events)
- RemoveAllUserSessniosAsync(sub) w RedisTicketStore wykorzystywany w Backchannel Logout
- ClaimsPrincipalExtensions aby w łatwy sposób otrzymać dane usera jako ClaimsPrincipals
- OIDC Back-Channel Logout 1.0: POST /auth/backchannel-logout — Keycloak woła ten endpoint przy unieważnieniu sesji po stronie IdP. Walidacja JWT (podpis z JWKS, iss, aud, iat, events, brak nonce, jti) + replay protection przez Redis. Wylogowuje usera ze wszystkich urządzeń w obrębie tej aplikacji (po sub); sid świadomie ignorujemy. Front-channel logout nie jest wspierany.


Konfiguracja po stronie Keycloak Admin Console (Clients → Settings):
- Backchannel Logout URL: https://<bff-host>/auth/backchannel-logout
- Backchannel Logout Session Required: ON
- Backchannel Logout Revoke Offline Sessions: opcjonalnie


nie robimy healthcheck dla Redisa ponieważ nie mam kubernetesa, nie ma jak tego wykorzystać