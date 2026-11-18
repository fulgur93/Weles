# Bezpieczeństwo

## Zasady użycia

WELES służy do legalnych audytów infrastruktury, do której masz uprawnienia.

- Każdy skan musi być przypisany do **jawnie zdefiniowanego i zatwierdzonego** zakresu (`ScanTarget.IsApproved`).
- Adresy publiczne wymagają osobnego, wyraźnego zezwolenia (`AllowPublicAddresses`).
- Wykluczenia mają pierwszeństwo przed allowlistą.
- WELES **nie** wykonuje exploitów, brute force, prób logowania ani testów destrukcyjnych. Wykrywanie (discovery)
  jest oddzielone od aktywnego testowania.
- AI nie może uruchamiać skanów ani operacji sieciowych bez zatwierdzenia użytkownika i nie ma dostępu do powłoki.

## Ochrona lokalnego panelu (zaimplementowane w Etapie 1)

| Zagrożenie | Mechanizm |
|------------|-----------|
| Dostęp z sieci LAN / Internetu | Kestrel nasłuchuje wyłącznie na `127.0.0.1`. |
| DNS rebinding | Odrzucanie żądań z nagłówkiem `Host` innym niż `127.0.0.1` / `localhost` (`AllowedHosts` + własna kontrola w `LocalAccessGuardMiddleware`) – HTTP 400. |
| Inni użytkownicy / procesy na tym samym komputerze | Losowy 256‑bitowy token generowany przy każdym starcie. Bez ciasteczka sesji każde żądanie (także pliki statyczne i WebSocket Blazora) dostaje HTTP 401. |
| CSRF, cross-site WebSocket hijacking | Ciasteczko `HttpOnly; SameSite=Strict`; odrzucanie żądań z obcym `Origin` lub `Sec-Fetch-Site: cross-site` (HTTP 403); antiforgery Blazora. |
| Wyciek tokenu | Token przekazywany raz przez `/auth?token=…`, następnie przekierowanie na `/`. Token trafia tylko do konsoli i pliku `instance.json` (`0600`), **nigdy do logów**. Porównanie w stałym czasie. |
| Klucze Data Protection | W katalogu danych użytkownika (`keys/`); na Windows dodatkowo szyfrowane DPAPI, na Linuksie chronione uprawnieniami katalogu `0700`. |
| Otwieranie przeglądarki | Tylko wewnętrznie wygenerowany adres loopback, przekazywany jako argument (bez interpretacji przez powłokę). |

## Dane

- Dane użytkownika wyłącznie w katalogu danych, nigdy w katalogu instalacyjnym.
- Logi nie zawierają haseł, kluczy ani tokenów.
- Lokalne AI działa offline; WELES nie wysyła danych infrastruktury do usług zewnętrznych.

## Planowane

- Walidacja importowanych archiwów (ZIP slip, limity rozmiaru, schemat) – Etap 9.
- Agenci: rejestracja jednorazowym kodem, tokeny przechowywane jako hash, unieważnianie, ograniczenie do przypisanych zakresów – Etap 10.
