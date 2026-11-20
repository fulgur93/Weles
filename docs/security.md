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
| Limity | `MaxHostsPerScan`, `MaxConcurrentConnections`, `ConnectionsPerSecond` (token bucket), na każdy host osobno `MaxConcurrentConnectionsPerHost` i `ConnectionsPerSecondPerHost`, timeouty połączeń/banerów/sond. Połączenia zamykane zwykłym FIN – zerwanie RST potrafi zawiesić usługi tanich routerów. |
| Zatrzymanie | Przycisk „Zatrzymaj skan” anuluje wszystkie sondy; zebrane wyniki są zapisywane, status `Zatrzymany`. |
| Audyt | `ScanEvent` (dziennik w bazie) + logi aplikacji: start, fazy, ostrzeżenia, zakończenie, błędy. |
| Brak testów ofensywnych | Tylko: TCP connect, ICMP echo, odczyt banera, `GET /`, handshake TLS, `PING`/`INFO server` (Redis, tylko gdy bez hasła – metadane), `SSLRequest` (PostgreSQL), negocjacja RDP. `CNXN` (ADB – bez odpowiedzi na wyzwanie AUTH), zapytanie DNS `version.bind` (CHAOS TXT), zapytania mDNS/DNS-SD (tylko sieć lokalna, wyniki filtrowane do zakresu). Bez logowania, bez brute force, bez exploitów. Sondy z danymi tylko na portach ich protokołów. |
| Dane z sieci są niezaufane | Banery i nagłówki są sanityzowane (drukowalne ASCII, limit długości), regexy z timeoutem, rozmiary odpowiedzi ograniczone. |

### Klucz hosta SSH

Na porcie z rozpoznanym banerem SSH skaner – jak `ssh-keyscan` – wysyła identyfikację klienta, listę algorytmów
(KEXINIT) i pierwszą wiadomość wymiany kluczy, odbiera publiczny klucz hosta i zamyka połączenie. Nie ma żadnej próby
uwierzytelnienia; klucz serwer pokazuje każdemu klientowi przed logowaniem. Służy wyłącznie do rozpoznania, że dwa adresy
to to samo urządzenie.

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

## Połączenia wychodzące (Etap 4)

WELES łączy się z Internetem **tylko** po kliknięciu „Aktualizuj z Internetu” w module Vulnerabilities:

| Host | Co pobiera |
|------|------------|
| `services.nvd.nist.gov` | CVE dla stałej listy produktów z katalogu WELES (np. `cpe:2.3:a:openbsd:openssh`) i producentów sprzętu (TP-Link) |
| `www.cisa.gov` | pełny katalog KEV (JSON) |
| `epss.empiricalsecurity.com` | pełny plik EPSS (CSV.gz), filtrowany lokalnie do CVE z bazy |

- Zapytania zawierają wyłącznie **stałą listę produktów** – nigdy wersji, modeli, adresów ani nazw wykrytych w sieci
  użytkownika. Nagłówek `User-Agent` jest ogólny (`WELES-vulnerability-feed/1.0`).
- Opcjonalny klucz API NVD (`Weles:Vulnerabilities:NvdApiKey`) jest wysyłany tylko do NVD i nie trafia do logów.
- Bez Internetu działa baza dołączona do aplikacji (`vulndb.json.gz`); UI zawsze pokazuje datę danych.
- Opisy CVE i referencje są danymi z zewnątrz: Blazor koduje je jako tekst, linki są ograniczone do `http(s)` i
  otwierane z `rel="noopener noreferrer"`.

## Lokalne AI (Etap 6)

- Silnik (Ollama) i model są dołączone do paczki; WELES uruchamia go jako proces potomny nasłuchujący wyłącznie na
  `127.0.0.1:11435`, z wyłączonymi funkcjami chmurowymi (`OLLAMA_NO_CLOUD`), bez dopuszczonych źródeł CORS poza stałą
  listą localhost Ollamy (strony z Internetu: 403; ochrona przed DNS rebinding: 403 dla obcego nagłówka Host).
- Model dostaje tylko dane z lokalnej bazy WELES wybrane do pytania; nic nie jest wysyłane poza komputer.
- Model nie ma narzędzi (brak tool calling): nie może uruchomić skanu, polecenia systemowego ani połączenia sieciowego.
  Skany uruchamia wyłącznie użytkownik w Wykrywaniu sieci, dla zatwierdzonego zakresu.
- Dane z sieci (banery, tytuły, nazwy urządzeń) są przed przekazaniem modelowi czyszczone i oznaczone jako dane – zasady
  każą ignorować zawarte w nich instrukcje. Odpowiedź jest renderowana po zakodowaniu HTML (bez skryptów i linków
  zewnętrznych).
- Rozmowy są przechowywane tylko w lokalnej bazie; można je usuwać.

## Planowane

- Walidacja importowanych archiwów (ZIP slip, limity rozmiaru, schemat) – Etap 9.
- Agenci: rejestracja jednorazowym kodem, tokeny przechowywane jako hash, unieważnianie, ograniczenie do przypisanych zakresów – Etap 10.
