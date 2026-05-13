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
- Endpointy które wystawia backend dla clienta /auth/login, /auth/logout, /auth/users/me
- Helper zapewniający ochorenę przed redirect
- Refresh Tokena w OnValidatePrincipal (Cookie events)
- RemoveAllUserSessniosAsync(sub) w RedisTicketStore które będzie wykorzystane w Backchannel
- ClaimsPrincipalExtensions aby w łatwy sposób otrzymać dane usera jako ClaimsPrincipals


nie robimy healthcheck dla Redisa ponieważ nie mam kubernetesa, nie ma jak tego wykorzystać