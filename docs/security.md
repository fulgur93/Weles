# Bezpieczeństwo

## Zasady użycia

WELES służy do legalnych audytów infrastruktury, do której masz uprawnienia.

- Każdy skan musi być przypisany do **jawnie zdefiniowanego i zatwierdzonego** zakresu (`ScanTarget.IsApproved`).
- Adresy publiczne wymagają osobnego, wyraźnego zezwolenia (`AllowPublicAddresses`).
- Wykluczenia mają pierwszeństwo przed allowlistą.
- WELES **nie** wykonuje exploitów, brute force, prób logowania ani testów destrukcyjnych. Wykrywanie (discovery)
  jest oddzielone od aktywnego testowania.
- AI nie może uruchamiać skanów ani operacji sieciowych bez zatwierdzenia użytkownika i nie ma dostępu do powłoki.

## Kontrole skanowania (zaimplementowane w Etapie 2)

| Wymaganie | Realizacja |
|-----------|------------|
| Jawny zakres, zatwierdzenie | `ScanTargetService.ApproveAsync` wymaga potwierdzenia uprawnień; `ScanEngine` ponownie sprawdza zatwierdzenie tuż przed startem. Edycja zakresu cofa zatwierdzenie. |
| Allowlista / wykluczenia | IP, CIDR (≤ /16), zakresy, domeny; wykluczenia mają pierwszeństwo i obejmują całą sieć. |
| Adresy publiczne | Odrzucane przy zapisie zakresu i pomijane przy skanie bez flagi `AllowPublicAddresses`; dotyczy też domen rozwiązujących się na adresy publiczne. Adresy zarezerwowane/multicast nigdy nie są skanowane. |
| Limity | `MaxHostsPerScan`, `MaxConcurrentConnections`, `ConnectionsPerSecond` (token bucket), timeouty połączeń/banerów/sond. |
| Zatrzymanie | Przycisk „Zatrzymaj skan” anuluje wszystkie sondy; zebrane wyniki są zapisywane, status `Zatrzymany`. |
| Audyt | `ScanEvent` (dziennik w bazie) + logi aplikacji: start, fazy, ostrzeżenia, zakończenie, błędy. |
| Brak testów ofensywnych | Tylko: TCP connect, ICMP echo, odczyt banera, `GET /`, handshake TLS, `PING`/`INFO server` (Redis, tylko gdy bez hasła – metadane), `SSLRequest` (PostgreSQL), negocjacja RDP. `CNXN` (ADB – bez odpowiedzi na wyzwanie AUTH), zapytanie DNS `version.bind` (CHAOS TXT), zapytania mDNS/DNS-SD (tylko sieć lokalna, wyniki filtrowane do zakresu). Bez logowania, bez brute force, bez exploitów. Sondy z danymi tylko na portach ich protokołów. |
| Dane z sieci są niezaufane | Banery i nagłówki są sanityzowane (drukowalne ASCII, limit długości), regexy z timeoutem, rozmiary odpowiedzi ograniczone. |

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
