1. Antiforgery na POST i może dodatkowy endpoint dla Frontendu aby dostać x-scrf-token
2. Dodać Możliwość zapisu accesstoken, refreshtoken i tokenid w Redis
3. wyciągnąć role z ID Token do roles poprzez OnTokenValidated? (zrobione)
4. Dodać ILoggera
5. Używać sesji z keycloaka
6. Jeśli użytkownik jest zalogowany odnawiać accesstoek poprzez refreshtoken
7. dodać backchannel logout
8. wprowadzenie DTO /auth/users/me (w przyszłośći zmiana na bibliotekę i aplikacja integrująca bibliotekę powinna sama )
    zmieniać wygląd DTO)
9. IUserInfoMapper<T> w DI — pozwolić konsumentowi biblioteki rejestrować własny mapper ClaimsPrincipal → TDto;
    domyślny mapper zwraca UserInfoDto, endpoint /auth/users/me korzysta z mappera z DI (Produces<TDto> dla OpenAPI).




Pamiętać:
1. że można konfigurować PostLogoutRedirectUri
2. Należy włączyć client roles dla idtoken w keycloak