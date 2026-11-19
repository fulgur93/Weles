# WELES – architektura

> **W**atchful **E**nterprise **L**ocal **E**nvironment **S**ecurity – Attack Surface Intelligence Platform.
> Dokument opisuje decyzje architektoniczne. Aktualizowany po każdym etapie.

## 1. Analiza wymagań – ryzyka techniczne

| # | Ryzyko | Skutek | Decyzja / mitygacja |
|---|--------|--------|---------------------|
| R1 | **Uprawnienia OS.** Surowe gniazda (ICMP, aktywne ARP) wymagają roota / Administratora. | Bez uprawnień nie da się wysłać własnych pakietów ARP/ICMP. | Discovery działa **bez uprawnień**: TCP connect + `System.Net.NetworkInformation.Ping` (na Linuxie .NET sam przechodzi na `ping` z systemu) + **pasywny odczyt tablicy ARP** (`/proc/net/arp`, `GetIpNetTable2` na Windows) po tym, jak próba połączenia zmusiła jądro do rozwiązania adresu MAC. Brak ICMP ≠ brak hosta. |
| R2 | Zapora Windows domyślnie blokuje ICMP. | Fałszywie „martwe” hosty. | Liveness = ICMP **lub** dowolna odpowiedź TCP (SYN-ACK albo RST) na porty sondujące 22/80/135/139/443/445/3389/8080. |
| R3 | **NVD API**: limity (5 żądań / 30 s bez klucza), pełna baza > 250 tys. CVE. | Długie pierwsze pobranie, brak danych offline. | Instalator dostarcza **snapshot** podatności dla produktów, które potrafimy rozpoznać (CPE: OpenSSH, Apache httpd, nginx, IIS, Samba, vsftpd, ProFTPD, Exim, Postfix, MySQL, MariaDB, PostgreSQL, Redis, MongoDB, OpenSSL, Dropbear, lighttpd, Tomcat, RouterOS, …) + pełne KEV + pełne EPSS. Aktualizacja przyrostowa (`lastModStartDate`) gdy jest Internet. UI zawsze pokazuje datę bazy. |
| R4 | **Backporty dystrybucyjne** (`OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`). | Fałszywe alarmy przy porównaniu samego numeru wersji. | Parser banerów wyciąga sufiks dystrybucji; przy jego obecności dopasowanie dostaje status **Wymaga weryfikacji**, nie **Potwierdzone**. |
| R5 | **Rozmiar paczki**: model Q4 ≈ 2,5 GB + Ollama z bibliotekami CUDA/ROCm ≈ 1–2 GB. | Paczka 4–5 GB; limit 2 GB na plik w GitHub Releases. | Dwa warianty: `cpu` (bez bibliotek GPU, ~3 GB) i `full` (z CUDA/ROCm/Vulkan). Na konkurs – nośnik USB + ZIP/TAR.GZ. |
| R6 | Blazor Server: obwód (circuit) żyje tylko, dopóki otwarta jest karta. | Skan przerwany po zamknięciu przeglądarki. | Skany wykonuje `BackgroundService` z kolejką; UI tylko subskrybuje postęp (in‑process event hub). |
| R7 | **Bezpieczeństwo localhost**: DNS rebinding, CSRF z dowolnej strony WWW, inni użytkownicy tego samego komputera. | Zdalne uruchomienie skanu przez złośliwą stronę. | Bind wyłącznie `127.0.0.1`; filtrowanie nagłówka `Host`; **token uruchomieniowy** (losowy, 256 bit) wymieniany na ciasteczko `HttpOnly; SameSite=Strict`; antiforgery Blazor; plik instancji z uprawnieniami 0600. Zaimplementowane w Etapie 1. |
| R8 | SQLite – równoległe zapisy skanera i odczyty UI. | `database is locked`. | Tryb WAL, `busy_timeout`, krótkożyjące konteksty przez `IDbContextFactory`, zapisy wsadowe ze skanera. |
| R9 | Halucynacje AI. | Wymyślone CVE/urządzenia. | AI dostaje wyłącznie kontekst zbudowany z bazy (z identyfikatorami), prompt wymusza „brak danych” zamiast zgadywania, odpowiedzi z identyfikatorami CVE są weryfikowane z bazą przed wyświetleniem. |
| R10 | Wydajność modelu na CPU w 2‑minutowym demo. | Długie oczekiwanie przed jury. | Model 4B Q4, rozgrzewka (`keep_alive`) przy starcie, strumieniowanie odpowiedzi, kontekst ograniczony do ~6 tys. tokenów. |
| R11 | Sieć na sali konkursowej (izolacja klientów Wi‑Fi, brak zgody na skan). | Pusta demonstracja albo skan bez uprawnień. | (a) **lokalne laboratorium** – `deploy/demo-lab` (Docker Compose z celowo starymi wersjami usług na 127.0.0.x / sieci bridge) daje **prawdziwe** wyniki skanu; (b) jawnie oznaczony **tryb demonstracyjny** z osobnym zbiorem danych (`IsDemo = true`, osobny plik bazy), nigdy nie mieszany z danymi rzeczywistymi. |
| R12 | Licencje komponentów. | Brak prawa do redystrybucji. | Ollama – MIT; Qwen3 – Apache 2.0; QuestPDF – Community License (darmowa < 1 mln USD przychodu – wystarczy na konkurs; alternatywa MIT: PDFsharp/MigraDoc). Dane NVD/KEV – domena publiczna (USA), EPSS – dozwolone użycie z atrybucją FIRST. Plik `THIRD-PARTY-NOTICES` w paczce. |

## 2. Architektura docelowa

**Modularny monolit**, jeden proces, bez mikroserwisów.

```
 Przeglądarka (http://127.0.0.1:5080, tylko localhost)
        │  SignalR (Blazor Interactive Server) + kilka endpointów (pobieranie plików)
        ▼
 ┌──────────────────────────── Weles.App (ASP.NET Core 10, Blazor) ─────────────────────────┐
 │  Components/Pages, Layout, Shared  ·  LocalAccessGuard  ·  hosting, Serilog, single‑instance │
 └──────────────┬───────────────────────────────────────────────────────────────────────────┘
                ▼
 ┌──────────── Weles.Infrastructure ─────────────┐        ┌───────── Weles.Core ─────────┐
 │ Database (EF Core + SQLite, migracje)          │ ─────▶ │ Entities, Enums, Interfaces,  │
 │ Discovery / Scanning (silnik C#, BackgroundSvc)│        │ Models, Rules (czysta logika, │
 │ Vulnerabilities (NVD, KEV, EPSS, matcher)      │        │ bez zależności od I/O)        │
 │ RiskAssessment · NetworkTopology · Reporting   │        └───────────────────────────────┘
 │ AI (IAiService → OllamaAiService)              │
 └──────┬────────────────────────────────────────┘
        ▼ proces potomny, 127.0.0.1:11435
   Ollama (dołączona) + model Q4 (dołączony)
```

Zasady:
- `Weles.Core` nie zależy od niczego (poza BCL). Reguły ryzyka i porównywanie wersji są tam, bo są czystą logiką i łatwo je testować.
- `Weles.Infrastructure` – cała komunikacja ze światem (sieć, pliki, baza, Ollama).
- `Weles.App` – UI i hosting. Komponenty nie rozmawiają bezpośrednio z siecią.
- AI jest za interfejsem `IAiService` – Ollamę można wymienić na llama.cpp (`llama-server` ma API zgodne z OpenAI) bez zmian w UI.
- JavaScript: tylko to, co dostarcza Blazor (`blazor.web.js`). Topologia sieci rysowana jako **SVG generowane w Blazorze**, z układem liczonym w C# (force‑directed) – bez biblioteki JS. Jeżeli okaże się niewystarczające, izolowany komponent z lokalnie dołączonym Cytoscape.js.
- Wszystkie zasoby UI (fonty, ikony) są lokalne – aplikacja działa offline.

### 2.1. Struktura solution

```
Weles/
├─ Weles.slnx
├─ Directory.Build.props            wspólne ustawienia (net10.0, nullable, wersja)
├─ dotnet-tools.json               dotnet-ef 10.x
├─ src/
│  ├─ Weles.App/                    Blazor Web App (Interactive Server), hosting
│  │  ├─ Program.cs
│  │  ├─ Hosting/                   porty, single-instance, przeglądarka, LocalAccessGuard
│  │  ├─ Components/{Layout,Pages,Shared}
│  │  └─ wwwroot/
│  ├─ Weles.Core/
│  │  ├─ Entities/  Enums/  Interfaces/  Models/  Rules/
│  ├─ Weles.Infrastructure/
│  │  ├─ Database/ (DbContext, konfiguracje, Migrations/)
│  │  ├─ Platform/ (ścieżki danych)
│  │  ├─ AI/  Discovery/  Scanning/  Vulnerabilities/  RiskAssessment/
│  │  └─ NetworkTopology/  Reporting/             (tworzone w swoich etapach)
│  └─ Weles.Agent/                  Worker Service – dopiero w Etapie 10
├─ tests/Weles.Tests/               xUnit: jednostkowe + integracyjne (WebApplicationFactory, SQLite)
├─ deploy/{windows,linux,demo-lab}/
└─ docs/
```

Odstępstwa od propozycji z założeń (uzasadnione):
- Nazwy projektów `Weles.*` (konwencja .NET PascalCase) zamiast `WELES.*`.
- Testy w `tests/`, a nie `src/` – standard, upraszcza publikację (`dotnet publish src/Weles.App`).
- `Repositories/` **nie powstaje** – `DbContext` jest już repozytorium/unit of work; dodatkowa warstwa nic by nie dała. Zapytania domenowe trafiają do serwisów zapytań (np. `DashboardQueries`).
- `Weles.Agent` nie jest tworzony w Etapie 1, by nie dodawać pustego projektu.
- `Layout/`, `Pages/`, `Shared/` są w `Components/` – tego oczekuje szablon Blazor Web App .NET 10.

## 3. Model AI i dystrybucja

### 3.1. Wybór modelu

| Model | Rozmiar Q4_K_M | Licencja | PL | Szybkość CPU* | Decyzja |
|-------|---------------:|----------|----|--------------:|---------|
| **Qwen3‑4B‑Instruct‑2507** | ~2,5 GB | Apache 2.0 | dobra | ~10–15 tok/s | **domyślny** |
| Bielik‑4.5B‑v3.0‑Instruct | ~2,9 GB | Apache 2.0 (do potwierdzenia przy pakowaniu) | bardzo dobra | ~9–13 tok/s | opcjonalny („polski”) |
| Qwen3‑8B | ~5,0 GB | Apache 2.0 | dobra | ~5–7 tok/s | wariant dla mocnych maszyn |
| Bielik‑11B‑v2.x | ~6,7 GB | Apache 2.0 | najlepsza | ~3–5 tok/s | odrzucony – za wolny na CPU w demo |

\* orientacyjnie, 8‑rdzeniowy CPU laptopa, DDR5.

**Rekomendacja: Qwen3‑4B‑Instruct‑2507 Q4_K_M** (tag Ollama `qwen3:4b-instruct-2507-q4_K_M`). Uzasadnienie: najlepszy stosunek jakości do rozmiaru w klasie ≤ 4B, tryb bez „thinking” (szybsze, przewidywalne odpowiedzi), stabilne generowanie JSON (potrzebne do ustrukturyzowanych podsumowań), permisywna licencja Apache 2.0 pozwalająca na redystrybucję w instalatorze. Bielik‑4.5B jako drugi dołączany model dla użytkowników, którzy chcą najlepszej polszczyzny – wybór w Ustawieniach. WELES **nie pobiera** modeli z Internetu.

### 3.2. Dołączanie Ollamy

- Źródło: oficjalne archiwa z GitHub Releases Ollamy (MIT): `ollama-windows-amd64.zip`, `ollama-linux-amd64.tgz` (+ `-rocm` opcjonalnie). Wersja przypięta w skrypcie budującym, suma SHA‑256 weryfikowana.
- Układ paczki:
  ```
  weles/
  ├─ Weles.App(.exe)                 self-contained .NET 10
  ├─ runtime/ollama/                 bin + lib/ollama (wariant cpu bez cuda_*/rocm)
  ├─ models/                         katalog OLLAMA_MODELS: manifests/ + blobs/
  └─ THIRD-PARTY-NOTICES.txt
  ```
- Katalog `models/` jest przygotowywany **w czasie budowania paczki**: `OLLAMA_MODELS=./models ollama pull <tag>` – w paczce lądują gotowe bloby, więc na komputerze użytkownika nic nie jest pobierane ani kopiowane.
- W czasie działania WELES uruchamia `ollama serve` jako **proces potomny**:
  `OLLAMA_HOST=127.0.0.1:11435` (inny port niż domyślne 11434, by nie kolidować z Ollamą użytkownika), `OLLAMA_MODELS=<instalacja>/models`, `OLLAMA_NOPRUNE=1` (katalog instalacji może być tylko do odczytu), `OLLAMA_ORIGINS=` (puste – brak CORS), `OLLAMA_NUM_PARALLEL=1`, `OLLAMA_KEEP_ALIVE=30m`.
  Windows: proces przypisany do Job Object (zabijany razem z WELES). Linux: `PR_SET_PDEATHSIG` przez wrapper albo zamknięcie przy `ApplicationStopping`.
- GPU: Ollama sama wykrywa CUDA/ROCm/Vulkan. Ustawienie „wymuś CPU” = `num_gpu: 0` w opcjach żądania. Brak założenia konkretnego producenta GPU.
- Brak dołączonej Ollamy → WELES próbuje skonfigurowanego endpointu; jeśli niedostępny – moduł AI pokazuje status „niedostępny”, reszta aplikacji działa normalnie.

## 4. Baza danych

SQLite w katalogu danych użytkownika, tryb WAL, migracje EF Core aplikowane automatycznie przy starcie. Czasy w UTC (`DateTime` z `Kind=Utc` – SQLite nie sortuje `DateTimeOffset`).

### 4.1. Model historii

Kluczowa decyzja: **rozdzielenie tożsamości od obserwacji**.

- `Asset` – trwała tożsamość urządzenia (dopasowywana po MAC, w drugiej kolejności IP + nazwa hosta). Ma stan „bieżący” (ostatni znany).
- `DiscoveredHost` / `DiscoveredPort` / `DiscoveredService` / `Certificate` – **niezmienne migawki z konkretnego skanu**. Nowy skan tworzy nowe wiersze; nic nie jest nadpisywane. Porównanie skanów = porównanie dwóch zbiorów migawek tego samego `Asset`.

### 4.2. Encje (Etap 1 – utworzone)

| Encja | Kluczowe pola | Relacje / ograniczenia |
|-------|---------------|------------------------|
| `ApplicationSetting` | `Key` (PK), `Value`, `UpdatedAt` | – |
| `ScanTarget` | `Name`, `IsApproved`, `ApprovedAt`, `AllowPublicAddresses`, `IsDemo` | 1‑N `ScanTargetEntry`, 1‑N `Scan` |
| `ScanTargetEntry` | `Value` (IP/CIDR/zakres/domena), `Kind`, `IsExclusion` | FK kaskadowo do `ScanTarget` |
| `Scan` | `Status`, `Trigger`, `PortSpecification`, `StartedAt`, `CompletedAt`, liczniki, `IsDemo` | FK `ScanTarget` (Restrict – zakresu ze skanami nie można usunąć), indeks `(Status, StartedAt)` |
| `NetworkSegment` | `Cidr` (unikalny), `Name`, `Gateway` | 1‑N `Asset` |
| `Asset` | `DisplayName`, `Hostname`, `PrimaryIpAddress`, `MacAddress`, `Vendor`, `AssetType`, `OsFamily`, `Criticality`, `CurrentRiskScore/Level`, `FirstSeenAt`, `LastSeenAt`, `IsDemo` | FK `NetworkSegment` (SetNull), indeksy MAC, IP |
| `DiscoveredHost` | `IpAddress`, `Hostname`, `MacAddress`, `Vendor`, `DiscoveryMethods` (flagi), `RoundTripMs`, `Ttl` | FK `Scan` (Cascade), FK `Asset` (SetNull), unikalny `(ScanId, IpAddress)` |
| `DiscoveredPort` | `Port`, `Protocol`, `State`, `Reason` | FK `DiscoveredHost` (Cascade), unikalny `(HostId, Port, Protocol)`, check `Port BETWEEN 1 AND 65535` |
| `DiscoveredService` | `ServiceName`, `Product`, `Vendor`, `Version`, `Cpe`, `Banner` (≤ 1024 zn.), `Confidence` (0–100), `DetectionMethod`, `IsTls` | 1‑1 z `DiscoveredPort` (Cascade), check `Confidence BETWEEN 0 AND 100` |
| `Certificate` | `Subject`, `Issuer`, `NotBefore`, `NotAfter`, `Thumbprint`, `SubjectAlternativeNames`, `KeyAlgorithm`, `KeySize`, `SignatureAlgorithm`, `TlsProtocol`, `IsSelfSigned`, `HostnameMatches` | FK `DiscoveredService` (Cascade), indeks `Thumbprint` |
| `Vulnerability` | `CveId` (unikalny), `Title`, `Description`, `CvssScore`, `CvssVector`, `CvssVersion`, `Severity`, `EpssScore`, `EpssPercentile`, `IsKnownExploited`, `KevDateAdded`, `KevRansomwareUse`, `Source`, `PublishedAt`, `LastModifiedAt`, `ReferencesJson`, `Weaknesses` (CWE) | 1‑N `VulnerabilityAffectedProduct` |
| `VulnerabilityAffectedProduct` | `Part` (a/o/h), `Vendor`, `Product`, `Version` (dokładna), `VersionStartIncluding/Excluding`, `VersionEndIncluding/Excluding`, `Condition` (warunek AND z konfiguracji CPE) | FK Cascade, indeks `(Vendor, Product)` |
| `AssetVulnerability` | `MatchStatus` (Potwierdzone/Prawdopodobne/Wymaga weryfikacji/Brak danych), `MatchConfidence`, `MatchReason`, `Status` (Open/Resolved/Accepted), `Port`, `Product`, `DetectedVersion`, `FirstDetectedAt`, `LastDetectedAt`, `ResolvedAt` | FK `Asset`, `Vulnerability`, opcjonalnie `DiscoveredService` i `Scan`; unikalny `(AssetId, VulnerabilityId)` – jedno dopasowanie na urządzenie i CVE (Etap 4) |
| `RiskFinding` | `RuleId`, `Title`, `Description`, `Category`, `Level`, `Score`, `Evidence`, `Recommendation` | FK `Scan` (Cascade), `Asset` (Cascade) |
| `RiskScore` | `Score`, `Level`, `BreakdownJson`, `CalculatedAt` | FK `Scan` (Cascade), `Asset` opcjonalny (null = Security Posture Score całej infrastruktury) |

### 4.3. Encje kolejnych etapów (zaprojektowane, dodawane migracją w swoim etapie)

| Encja | Etap | Zarys |
|-------|------|-------|
| `NetworkInterface` | – | **Nie tworzona.** Historia adresów urządzenia wynika z niezmiennych obserwacji (`DiscoveredHost`) – oś czasu pokazuje zmiany IP/MAC; osobna encja nie wnosiłaby danych. Wróci, jeśli agenci (Etap 10) zaczną raportować wiele interfejsów jednego hosta. |
| `SoftwareVersion` | 4 | znormalizowany katalog `(Vendor, Product, Version, Cpe)` współdzielony przez usługi; do tego czasu pola leżą w `DiscoveredService` |
| `NetworkRelationship` | 7 | `SourceAssetId`, `TargetAssetId`, `Kind` (same‑segment, gateway, reachable‑service), `Evidence`, `Confidence`, `ScanId` |
| `AttackPath` + `AttackPathStep` | 7 | uporządkowane kroki z `Justification` i `Confidence`, `IsHypothetical = true` zawsze, dopóki nie ma dowodu |
| `Domain` | 8 | nazwa, rodzaj (apex/sub), źródło (DNS, CT), rekordy DNS jako JSON, FK `ScanTarget` |
| `AuditReport` | 9 | `ScanId`, `Format`, `FilePath`, `Sha256`, `CreatedAt`, `AiSummary` |
| `AIConversation`, `AIMessage` | 6 | rozmowy + wiadomości (`Role`, `Content`, `ContextSnapshotJson`, `Model`, `TokensIn/Out`) |
| `Agent`, `AgentScan` | 10 | `Name`, `TokenHash` (nigdy jawny token), `Status`, `LastSeenAt`, `RevokedAt`, dozwolone zakresy |

### 4.4. Zmiany w Etapie 2 (migracja `Stage2Discovery`)

- `ScanEvent` – dziennik skanu (start, fazy, ostrzeżenia, zatrzymanie, błędy), kaskadowo z `Scan`.
- Migracja `Stage2Mdns`: `DiscoveredHost.AnnouncedServicesJson` (usługi ogłaszane przez mDNS); `AssetType.MobileDevice`, `DiscoveryMethod.Mdns`.
- `Scan`: `HostsTargeted`, `HostsProbed`, `PortCount`, `ScopeSnapshot` (zakres w chwili skanu – zakres można później edytować), `SettingsJson` (użyte limity).
- `DiscoveredHost`: `IsGateway`, `AssetTypeGuess`, `ClassificationConfidence`, `ClassificationReasons`; `Asset.ClassificationReasons`; `ScanTarget.UpdatedAt`.
- Zapisywane są wyłącznie porty **otwarte**; zamknięcie portu w Monitoringu = brak portu w kolejnym skanie.

## 5. Silnik discovery (Etap 2)

```
ScanTargetService.StartScanAsync ──► ScanCoordinator (kolejka, stop, postęp) ──► ScanWorker (BackgroundService, 1 skan naraz)
                                                                                    │
                                                                                    ▼
ScanEngine: ScopeResolver ─► wykrywanie hostów ─► tablica ARP ─► porty ─► reverse DNS ─► ServiceProber ─► AssetClassifier ─► ScanResultWriter
```

| Faza | Technika | Uprawnienia |
|------|----------|-------------|
| Zakres | `TargetParser` (IP, CIDR ≤ /16, zakres, IPv6, domena), wykluczenia wygrywają, adresy publiczne tylko ze zgodą, zarezerwowane/multicast nigdy, limit `MaxHostsPerScan` | – |
| Hosty | ICMP (`Ping`, na Linuksie przez systemowy `ping`) **lub** TCP connect na porty sondujące – RST też dowodzi istnienia hosta; następnie odczyt tablicy ARP (`/proc/net/arp`, `GetIpNetTable`) – hosty bez odpowiedzi, ale z wpisem ARP, są oznaczane metodą ARP | brak |
| Porty | TCP connect, `ConnectionGate` globalnie (równoległość + token bucket) **i osobno na każdy host** (domyślnie 10 równoległych, 20 połączeń/s); zamknięcie zwykłym FIN, nigdy RST (zob. dziennik decyzji 2026‑11‑19) | brak |
| Usługi | baner pasywny → sondy protokołów tylko na ich portach (Redis `PING`/`INFO server`, PostgreSQL `SSLRequest`, RDP X.224 z wykrywaniem NLA) → `GET /` → TLS (certyfikat, protokół, szyfr, próba TLS 1.0/1.1) → HTTP po TLS | brak |
| Producent | Rejestr IEEE MA-L osadzony w aplikacji (`oui.csv.gz`, ~26,5 tys. wpisów, odświeżanie `deploy/tools/update-oui.sh`) + prefiksy wirtualizacji; MAC losowe/lokalne oznaczane | – |
| Klasyfikacja | `AssetClassifier` – typ i system z listą powodów (banery, porty, TTL, producent, brama, interfejs WWW) | – |

Zasady rozpoznawania:
- **Numer portu nigdy nie daje produktu ani wersji** (`port-hint`, pewność ≤ 25).
- Pewność: baner/protokół z wersją 90–95, produkt bez wersji 70–85, rozpoznany protokół 60–70, nierozpoznany baner 25.
- CPE tworzony tylko przy znanym produkcie **i** wersji (`8.9p1` → `8.9:p1` jak w NVD).
- Sufiks dystrybucji (`Ubuntu-3ubuntu0.10`, `+deb12u3`, `(Ubuntu)`) zapisywany jako `distribution` – podstawa statusu „Wymaga weryfikacji” w Etapie 4.
- Brak udanego handshake TLS 1.0/1.1 jest **niejednoznaczny** (polityka OpenSSL klienta) – raportowana jest tylko potwierdzona akceptacja.

Weryfikacja na prawdziwej sieci (192.168.0.0/24, 2026‑11‑18, za zgodą właściciela): 11 urządzeń z 254 adresów
(router TP‑Link, punkt dostępowy Tenda, 2 dekodery ADB, radio internetowe Frontier Silicon, Chromecast/Android TV,
telefony z losowym MAC, komputer z WELES), skan Szybki ~18 s, Standardowy ~21 s; 3 kolejne skany → 33 obserwacje,
11 zasobów (korelacja bez duplikatów). Dekodery bez odpowiedzi ICMP wykryte przez TCP + ARP.
Druga sieć (przewodowa, 2026‑11‑19, za zgodą): 3 urządzenia (router TP‑Link TL‑WR841N v9, telefon z losowym MAC,
komputer z WELES); 4 skany (Szybki, Standardowy, Mobilny, Standardowy fragmentu .1–.50) → 3 zasoby, statusy poprawne
(fragment sieci nie oznaczył pozostałych jako nieobecnych). Test ujawnił zawieszanie usług routera przez zamykanie
połączeń RST – naprawione (dziennik decyzji).

Zasada dla DNS: wersja z `version.bind` może należeć do serwera nadrzędnego (router przekazujący zapytania) – pewność 55
i flaga `dns.versionNote`; Etap 4 musi traktować dopasowania o pewności < 70 jako „Wymaga weryfikacji”.

### 5.1. Urządzenia mobilne i mDNS

- Profil portów `mobile` = profil szybki + usługi zostawiane włączone na telefonach: ADB przez TCP (5555), serwery FTP
  aplikacji do udostępniania plików (2121, 2221), SSH Termux (8022), AirDroid (8888/8889), KDE Connect (1714–1764),
  synchronizacja iPhone (62078), AirPlay (7000).
- Sonda ADB wysyła wyłącznie pakiet `CNXN` (pierwszy krok `adb connect`) i odczytuje odpowiedź: `AUTH` = ADB włączone
  z autoryzacją, `CNXN` = ADB **bez** autoryzacji (+ model urządzenia). WELES nigdy nie odpowiada na wyzwanie AUTH
  i nie wysyła klucza – na telefonie nie pojawia się okno autoryzacji i nie powstaje sesja.
- mDNS/DNS-SD (`MdnsDiscovery`): zapytania „legacy unicast” z portu efemerycznego do 224.0.0.251:5353 (bez zajmowania
  portu 5353), dwie rundy – enumeracja typów + lista typów istotnych (`MdnsServiceCatalog`). Wyniki są filtrowane do
  zatwierdzonego zakresu. Porty ogłoszone przez urządzenie są zawsze skanowane – tak wykrywane jest debugowanie
  bezprzewodowe Androida (losowy port, `_adb-tls-connect._tcp`).
- Z sieci **nie da się** ustalić wersji Androida/iOS, poziomu poprawek ani zainstalowanych aplikacji – do tego potrzebny
  byłby agent na urządzeniu lub MDM. WELES ocenia wyłącznie to, co telefon wystawia w sieci.
- Weryfikacja na żywo (2026‑11‑18): mDNS ujawnił radio „DigitRadio 140” i Android TV „kuchnia” wraz z portem 6466,
  którego nie ma w żadnym profilu; telefon Xiaomi nie ogłaszał usług i miał zamknięte wszystkie 65 535 portów TCP.

Ograniczenia znane po Etapie 2: brak UDP poza mDNS (SNMP, NetBIOS-NS, SSDP), brak SMB negotiate (wersja SMB/SMBv1 – Etap 5), brak STARTTLS dla SMTP/IMAP, MongoDB rozpoznawane tylko z portu.

## 5a. Inwentarz urządzeń (Etap 3)

- **Pola ręczne** (`CustomName`, `UserAssetType`, `Criticality`, `Notes`, migracja `Stage3Assets`) nigdy nie są
  nadpisywane przez skan. `DisplayName` = nazwa użytkownika albo nazwa automatyczna (host → „producent (IP)” → IP).
  Wykryty typ (`AssetType`) nadal się aktualizuje, a obowiązuje `EffectiveType = UserAssetType ?? AssetType`.
- **Status urządzenia** (`AssetStatusRules`) liczony względem *ostatniego zakończonego skanu, który objął jego adres*
  (zakres odtwarzany ze `ScopeSnapshot`) lub w którym urządzenie zaobserwowano: Nowe / Aktywne / Nieobecne /
  Poza ostatnimi skanami / Nieznane. Skan innej sieci nie czyni urządzenia „nieobecnym”, ale jeśli po skanie jego sieci
  wykonano skan innej rozpoznanej sieci, status to „Nieznane” (skany bez identyfikacji sieci, np. loopback, się nie liczą); skany przerwane i zatrzymane się nie liczą.
  „Aktywne” obejmuje też „Nowe” (urządzenie widziane po raz pierwszy jest obecne).
- **Tożsamość sieci** (`NetworkIdentity`, `Scan.NetworkFingerprint`, migracja `Stage3NetworkIdentity`) – adres MAC bramy
  sieci, w której wykonano skan. Zakresy prywatne się powtarzają (192.168.0.0/24 w domu i w biurze), więc skan obejmuje
  urządzenie tylko w jego własnej sieci, a dopasowanie „po IP i nazwie” (urządzenia bez MAC) też wymaga tej samej sieci.
  Migracja uzupełnia odcisk starych skanów z bramy zaobserwowanej w danym skanie. Nieznany odcisk = sieci nierozróżnialne.
- **Sieć = segment** (`NetworkSegment.GatewayMac`, migracja `Stage3NetworkSegments`): segment to zakres CIDR *w konkretnej
  sieci* (unikalny indeks Cidr + GatewayMac), więc 192.168.0.0/24 w domu i w biurze to dwa segmenty, a każde urządzenie
  należy do sieci swojej ostatniej obserwacji. Migracja rozdziela dawne wspólne segmenty według tej zasady.
- **Bieżąca sieć** (`CurrentNetworkProvider`) – z interfejsów i pamięci ARP (bez wysyłania ruchu). Widok domyślny listy
  ukrywa wyłącznie segmenty *innych rozpoznanych* sieci; urządzenia bez segmentu (127.0.0.1, podsieci routowane/VPN)
  i segmenty bez znanej bramy pozostają widoczne. Kolumna „Sieć” i wybór sieci w filtrze.
- **Ten komputer** – znaleziony pod adresem sieciowym (nie 127.0.0.1) jest jednym zasobem niezależnie od karty
  (Wi‑Fi / kabel): zasoby z adresami MAC jego interfejsów są łączone w najstarszy (obserwacje, ustalenia, pola ręczne
  zachowane). Skan 127.0.0.1 pozostaje osobnym zasobem – usługi nasłuchujące tylko lokalnie to inna powierzchnia ataku.
- **Model urządzenia** (`DeviceModel`, pole `Asset.Model`, migracja `Stage3DeviceModel`) – tylko gdy urządzenie samo go
  podaje (realm HTTP Basic, nagłówek UPnP `TL-WR841N/9.0`, tytuł, ADB). Liczba po modelu w nagłówku UPnP to wersja
  sprzętu, a nie oprogramowania – nie trafia do pola wersji, żeby nie zafałszować dopasowań CVE w Etapie 4. Nazwa
  automatyczna: host → „model (IP)” → „skrócony producent (IP)” → IP.
- **Stan portów** (`ObservationComparer.Replay`) – każdy port ma stan z ostatniego skanu, który go *sprawdzał*
  (profil portów skanu). Skan Szybki po Standardowym nie „zamyka” portów spoza swojej listy, a kolejny Standardowy nie
  ogłasza ich jako „nowych”; aktualne usługi i liczba portów na liście łączą obserwacje według tej samej zasady.
- **Historia zmian** (`ObservationComparer`) – porównanie kolejnych obserwacji: IP, nazwa hosta, MAC, typ, otwarte
  i zamknięte porty, zmiana produktu, zmiana wersji, nowy certyfikat; oś czasu zawiera też skany, które objęły adres
  i nie znalazły urządzenia.
- **Lista** (`AssetQueries` + `AssetListEngine`) – dane ładowane raz, filtrowanie/sortowanie w pamięci: wyszukiwanie
  wielu słów (AND) po nazwie, IP, MAC, producencie, systemie, segmencie, produktach i numerze portu, bez wielkości liter
  i polskich znaków (z jawnym ł → l); facety z licznikami; sortowanie wielokolumnowe (Shift+klik); paginacja; wybór
  kolumn zapisany w `ApplicationSetting` (`ui.assets.columns`).

## 5b. Vulnerability Intelligence (Etap 4)

| Element | Implementacja |
|---------|---------------|
| Źródła | NVD CVE API 2.0 (`virtualMatchString` = CPE produktu z `ProductCatalog` + aliasy dawnych nazw producenta, np. `nginx:nginx`, `mysql:mysql`, `redislabs:redis`; dla sprzętu cały producent `cpe:2.3:h:tp-link` / `o:tp-link`), CISA KEV (pełny JSON), FIRST EPSS (pełny CSV.gz filtrowany do CVE z bazy). MITRE CVE – przez rekordy NVD (to te same identyfikatory i opisy). MITRE ATT&CK – Etap 5/6 (mapowanie technik do ryzyk i wyjaśnień AI). |
| Offline | `tools/Weles.VulnDbBuilder` (uruchamiany przez `deploy/tools/update-vulndb.sh`) buduje `Vulnerabilities/Data/vulndb.json.gz` – zasób osadzony w `Weles.Infrastructure` (2026‑11‑19: 5064 CVE, 56 w KEV, EPSS dla wszystkich, 1,1 MB). `VulnerabilityStartupService` importuje go w tle przy starcie (≈ 5 s), jeśli dane w bazie są starsze; nowszych danych pobranych online nie nadpisuje. |
| Aktualizacja | Tylko na żądanie użytkownika (`VulnerabilityDatabaseService.StartOnlineUpdate`): NVD przyrostowo (`lastModStartDate/EndDate`, maks. 119 dni; nowe zapytanie katalogu – pełne), limit 6,5 s między żądaniami bez klucza (0,7 s z kluczem), ponawianie 403/429/5xx; KEV jako pełny katalog (CVE usunięte z KEV tracą flagę); EPSS. Błąd jednego źródła nie przerywa pozostałych; stan każdego źródła i data w `ApplicationSetting` `vulndb.state`. |
| Parser | `NvdCveParser`: odrzucone CVE pomijane; CVSS v3.1 → v4.0 → v3.0 → v2 (ocena NVD „Primary” przed CNA); konfiguracje CPE: każdy `vulnerable` wpis → `AffectedProductRecord`, węzły AND → `Condition`, węzły zanegowane pomijane; referencje tylko http(s), maks. 12. |
| Wersje | `VersionComparer`: liczby numerycznie, końcowe zera bez znaczenia (`1.0` = `1.0.0`), `alpha/beta/rc/pre/dev` przed wydaniem, sufiksy `p1`, litery OpenSSL po wydaniu, znaczniki `-log` pomijane. Dokładny wpis NVD (`openssh:9.3:-`) nie obejmuje `9.3p2` – to wydanie z poprawką. |
| Dopasowanie | `VulnerabilityMatcher` (Core, bez I/O): producent **i** produkt CPE muszą się zgadzać, wersja musi być w zakresie. Status: *Potwierdzone* – rozpoznanie ≥ 90%, dokładna wersja, bez warunków; *Prawdopodobne* – rozpoznanie 70–89% lub warunek AND (np. system); *Wymaga weryfikacji* – sufiks dystrybucji (backporty), wersja mniej dokładna niż granica zakresu, brak zakresu w NVD, uwaga o wersji (DNS `version.bind` może należeć do serwera nadrzędnego) lub rozpoznanie < 70%; *Brak wystarczających danych* – model sprzętu z NVD (`h:tp-link:tl-wr841n`, z uwzględnieniem rewizji `v9`) bez znanej wersji firmware – z zakresem podatnego firmware w uzasadnieniu. Usługa bez wersji nie daje dopasowań (to byłby szum, nie dowód). |
| Cykl życia | `VulnerabilityMatchingService` po każdym skanie (`ScanWorker`) i po aktualizacji bazy: dowody z aktualnych portów urządzenia (`ObservationComparer.Replay` – port nieobjęty profilem ostatniego skanu zachowuje stan) i z `Asset.Model`. Nowe dopasowanie → *Otwarte*; dowód zniknął → *Rozwiązane* (`ResolvedAt`); powrót dowodu → ponowne otwarcie tego samego rekordu; *Zaakceptowane* przez użytkownika zostaje. `MatcherVersion` wymusza ponowne dopasowanie po zmianie reguł. |
| UI | `/vulnerabilities` – stan bazy z datą każdego źródła, aktualizacja z postępem i przerwaniem, lista dopasowań (filtry statusu, KEV, rozwiązane, wyszukiwanie); `/vulnerabilities/{CVE}` – opis, CVSS, EPSS, KEV, zakresy, referencje, urządzenia z uzasadnieniem, akceptacja ryzyka; tabela podatności w szczegółach urządzenia. Liczniki na pulpicie i liście urządzeń pomijają „Brak wystarczających danych”. |

Weryfikacja na kopii bazy użytkownika (2026‑11‑19, 14 urządzeń, 2 sieci): import 5064 CVE w 4,7 s, 0 dopasowań –
poprawnie: jedyna usługa z wersją z katalogu to BIND 9.20.26 na routerze (najnowsza poprawka w NVD dla gałęzi 9.20 to
9.20.23), MicroStack (radio internetowe) nie ma CPE w katalogu, a model routera nie został zapisany w tych skanach.
Zapytanie przyrostowe NVD sprawdzone na żywo (47 zmian OpenSSH od 2026‑08‑01).

## 5b'. Risk Engine (Etap 5)

| Element | Implementacja |
|---------|---------------|
| Reguły konfiguracji | `RiskRules` (Core): 24 reguły z dowodem z sieci – ADB bez autoryzacji, API Dockera, Redis bez hasła, panel administracyjny w sieci, Telnet, HTTP Basic / logowanie bez TLS, FTP, RDP (bez NLA), VNC, SMB, bazy danych, PostgreSQL bez SSL, MQTT, TLS 1.0/1.1, certyfikaty (wygasły, słaby klucz, samopodpisany, zła nazwa), UPnP, nagłówki HTTP, ujawnianie wersji. Każda ma kategorię, ocenę bazową, zalecenie i techniki MITRE ATT&CK. Reguła „usługa dostępna” oparta tylko na numerze portu ma pewność 60 i wagę × 0,8. Panel administracyjny bez uwierzytelnienia HTTP to *ekspozycja* (40), nie „dostęp bez hasła” – logowanie bywa formularzem na stronie. |
| Ocena problemu | CVE: CVSS × 10 (+20 CISA KEV, +4/10/15 przy EPSS ≥ 1/10/50%) × pewność dopasowania (1,0 / 0,85 / 0,6 / 0,25); CVE jednego produktu na jednym porcie = jedna pozycja naprawy (+1 za każde kolejne CVE, maks. +10). Konfiguracja: ocena bazowa reguły. |
| Ocena urządzenia | najpoważniejszy problem + 10% pozostałych (maks. +15) → × krytyczność (0,8 / 1 / 1,15 / 1,3) → + rola (brama/router +8, serwer/NAS/urządzenie sieciowe +5) → + ekspozycja (adres publiczny +15, UPnP na routerze +5; dla sieci lokalnej czynnik „nie badano”, 0 pkt) → + usługi (> 5 portów, maks. +8) → + wiek oprogramowania (najstarsza niezałatana CVE ≥ 2 lata +3, ≥ 5 lat +6) → + zmiany (nowe porty od poprzedniego skanu +5). Poziomy: ≥ 80 Critical, ≥ 60 High, ≥ 35 Medium, ≥ 15 Low, inaczej Informational. Każdy krok zapisany jako `RiskFactor` – UI pokazuje pełne wyliczenie. |
| Security Posture Score | dla sieci skanu: 100 − (½ najbardziej zagrożonego urządzenia + ½ średniej pięciu najbardziej zagrożonych); zapisywany per skan (`RiskScore` z `AssetId = null`), więc trend to prawdziwa historia. |
| Priorytety napraw | priorytet = ocena problemu × krytyczność + kontekst urządzenia (rola, ekspozycja, usługi, wiek, zmiany); sortowanie po priorytecie, potem KEV. |
| Cykl życia | `RiskAssessmentService` po każdym skanie (po dopasowaniu podatności), po aktualizacji bazy podatności i przy zmianie `EngineVersion`: `RiskFinding` – jedno na (urządzenie, reguła, port), otwierane/rozwiązywane/ponownie otwierane; „Zaakceptowane” przez użytkownika nie wlicza się do oceny (czynnik „zaakceptowane ryzyka”) i wywołuje natychmiastową ponowną ocenę. Teksty zapisywane z formatowaniem niezależnym od kultury („CVSS 9.8”). |
| UI | `/risk` – Security Posture Score każdej sieci z czynnikami i zmianą od poprzedniego skanu, trend (SVG bez JavaScriptu), priorytety napraw z uzasadnieniem, zaleceniem, CVE i ATT&CK, ranking urządzeń; szczegóły urządzenia – wyliczenie oceny, problemy do naprawy, problemy konfiguracji z akceptacją; pulpit – wynik, krytyczne problemy, 3 priorytety. |

Weryfikacja na kopii bazy użytkownika (2026‑11‑19): sieć przewodowa 47/100 (Raspberry Pi 84 – OpenSSH 8.4p1 Debian, 35 CVE „Wymaga weryfikacji”, w tym 1 z KEV, najstarsza z 2021 r.), sieć domowa 62/100 (router 52 – panel w sieci, certyfikat samopodpisany, nagłówki, ujawniona wersja DNS); wszystkie strony po angielsku bez polskiego tekstu.

## 5c. Język interfejsu (PL / EN)

- Polski jest językiem źródłowym: każdy tekst w kodzie jest po polsku i jest jednocześnie kluczem słownika
  (`Weles.App/Localization/en.json`, ~670 wpisów). Brak tłumaczenia oznacza tekst polski, nigdy surowy klucz.
- `L.T("…")` – tekst stały, `L.F("… {0}", x)` – z parametrami (formatowanie w kulturze języka), `L.Message(tekst)` –
  komunikaty zapisane wcześniej po polsku przez Core/Infrastructure (zdarzenia skanu, uzasadnienia klasyfikacji i
  dopasowań, błędy walidacji, automatyczne nazwy zakresów): dokładny wpis, potem wzorce z `{0}…{n}` (argumenty
  tłumaczone rekurencyjnie), a teksty złożone dzielone na wierszach, `" | "`, `"; "`, `" – "` i `", "`. Dzięki temu
  przełączenie języka działa także dla danych z wcześniejszych skanów – bez migracji i bez zapisywania kluczy w bazie.
- `LanguageState` (ustawienie `ui.language`) + własny `RequestCultureProvider`: każde żądanie, także połączenie obwodu
  Blazor, dostaje `pl-PL` albo `en-GB`; przełączenie przeładowuje stronę (nowy obwód w nowej kulturze).
- Testy: każdy literał `L.T/L.F` w `Weles.App` ma tłumaczenie, placeholdery się zgadzają, tłumaczenia nie zawierają
  polskich liter; teksty generowane przez rdzeń (uzasadnienia dopasowań i klasyfikacji, błędy walidacji, historia
  zmian) i prawdziwe komunikaty z bazy użytkownika tłumaczą się bez polskich słów; wszystkie strony renderowane po
  angielsku (także na kopii bazy użytkownika: 36 stron) nie zawierają polskiego tekstu.

## 6. Bezpieczeństwo aplikacji (Etap 1)

- Kestrel nasłuchuje **wyłącznie** na `127.0.0.1` (port 5080 albo pierwszy wolny).
- `HostFiltering`: akceptowane tylko `127.0.0.1`, `localhost` (ochrona przed DNS rebinding).
- `LocalAccessGuard`: każde żądanie musi mieć ciasteczko sesji powiązane z losowym tokenem uruchomieniowym. Token trafia do przeglądarki jednorazowo przez `/auth?token=…`, potem przekierowanie na `/` (token znika z paska adresu). Porównanie w stałym czasie.
- Plik instancji (`instance.json`: PID, port, token) – pozwala drugiemu uruchomieniu otworzyć istniejące okno zamiast startować drugi serwer; na Linuksie uprawnienia `0600`.
- Logi nie zawierają tokenu (logowany jest jedynie adres bez parametrów).

## 7. Plan realizacji

| Etap | Zakres | Demo MVP? |
|------|--------|-----------|
| 1 | Fundament: solution, Blazor, EF Core + SQLite, migracje, ścieżki danych, Serilog z rotacją, bezpieczny hosting localhost, layout, dashboard (dane z bazy), ustawienia | ✅ |
| 2 | Network Discovery: interfejsy, CIDR, zakresy z zatwierdzaniem, ICMP/TCP/ARP, porty, banery, TLS, HTTP, zapis do bazy, postęp na żywo, zatrzymanie | ✅ (laboratorium demo → Etap 4: `deploy/demo-lab`) |
| 3 | Assets: tabela (szukanie, sortowanie, filtry, paginacja, kolumny), szczegóły, historia, pola ręczne, status obecności | ✅ |
| 4 | Vulnerability Intelligence: NVD/KEV/EPSS, snapshot offline, matcher wersji ze statusami | ✅ |
| 5 | Risk Engine: reguły, scoring z wyjaśnieniem, Security Posture Score, trend, priorytety napraw, MITRE ATT&CK | ✅ |
| 6 | AI Security Analyst: Ollama jako proces potomny, model, czat ze strumieniowaniem, kontekst z bazy | ✅ |
| 7 | Monitoring (diff skanów, harmonogram) + Topology (SVG) + Attack Paths | diff ✅, reszta ⏸ |
| 8 | External Attack Surface: DNS, subdomeny (CT), certyfikaty | ⏸ |
| 9 | Raporty PDF, eksport/import JSON/ZIP | PDF ✅ |
| 10 | Agenci (Worker Service, HTTPS, rejestracja, unieważnianie) | ⏸ |
| 11 | Pakowanie: ZIP/TAR.GZ → instalatory (Inno Setup / AppImage+DEB), Ollama + model | ZIP/TAR.GZ ✅ |

**Konieczne do pierwszej demonstracji:** etapy 1–6, porównanie skanów z etapu 7, PDF z etapu 9, paczki ZIP/TAR.GZ z etapu 11, laboratorium demo.
**Można odłożyć:** topologia i ścieżki ataku (efektowne, ale nie w krytycznej ścieżce 2‑minutowego scenariusza), external attack surface, import audytu, agenci, instalatory MSI/DEB, aktualizator.

## 8. Dziennik decyzji

| Data | Decyzja |
|------|---------|
| 2026‑11‑18 | Pakiety przypięte do linii 10.x (EF Core 11 wymaga net11). |
| 2026‑11‑18 | Brak warstwy repozytoriów; `IDbContextFactory<WelesDbContext>` w serwisach. |
| 2026‑11‑18 | Serilog (plik, rotacja dzienna + limit rozmiaru, 14 plików) – wbudowany logger .NET nie ma sinka plikowego. |
| 2026‑11‑18 | Motyw jasny/ciemny bez JS: klasa CSS na korzeniu layoutu, preferencja w `ApplicationSetting`. |
| 2026‑11‑18 | Content root = katalog aplikacji (`AppContext.BaseDirectory`), nie bieżący katalog – inaczej uruchomienie ze skrótu gubi `appsettings.json` i `wwwroot` (wykryte w teście uruchomieniowym). |
| 2026‑11‑18 | Plik wykonywalny nazywa się `Weles` / `Weles.exe` (`AssemblyName`), przestrzenie nazw pozostają `Weles.App`. |
| 2026‑11‑18 | Paczka self-contained linux-x64 bez AI: 53 MB (tar.gz), ReadyToRun; zweryfikowane uruchomienie bez systemowego .NET. |
| 2026‑11‑18 | Ping z domyślnym buforem: bez `CAP_NET_RAW` .NET na Linuksie używa systemowego `ping`, który odrzuca własny bufor (`PlatformNotSupportedException`) – wykryte przy skanie na żywo, dodany test regresji. |
| 2026‑11‑18 | CUPS nie oznacza drukarki (serwer wydruku na większości desktopów Linux/macOS) – wykryte przy skanie na żywo. |
| 2026‑11‑18 | Wykluczenie CIDR obejmuje całą sieć (również adres sieci i broadcast). `Apache-Coyote` = Tomcat, nie Apache httpd. |
| 2026‑11‑18 | Sondy wysyłające dane (Redis, PostgreSQL, RDP) tylko na ich standardowych portach – nie wysyłamy obcych protokołów do nieznanych usług. |
| 2026‑11‑18 | Skany wykonywane sekwencyjnie (jeden naraz) – przewidywalne obciążenie sieci i SQLite; równoległość wewnątrz skanu ograniczona `ConnectionGate`. |
| 2026‑11‑18 | Laboratorium demo (Docker) przesunięte do Etapu 4 – wtedy stare wersje usług dają widoczne dopasowania CVE; na maszynie deweloperskiej brak Dockera. |
| 2026‑11‑18 | Rejestr OUI z `oui.txt` zamiast `oui.csv` – CSV z IEEE zawierał 26,5 tys. z 39,2 tys. przypisań (brakowało m.in. Frontier Silicon), wykryte na prawdziwej sieci. |
| 2026‑11‑18 | Jedno przekierowanie HTTP w obrębie tego samego schematu/hosta/portu (walidacja `Location` – brak znaków sterujących, limit długości); inne hosty nigdy. |
| 2026‑11‑18 | Nieznany nagłówek `Server` bez wersji nie tworzy produktu (np. „BH”, „Http Server”); w nagłówkach UPnP pomijane są znaczniki protokołu/systemu. UPnP nie jest „panelem administracyjnym”. |
| 2026‑11‑18 | Wskazówki z certyfikatu TLS (np. `CN=tplinkwifi.net`, `OU=Widevine`) używane do rozpoznania urządzenia; własny komputer rozpoznawany po adresach interfejsów; nazwy `_gateway` z systemd-resolved odrzucane. |
| 2026‑11‑19 | Lista urządzeń filtrowana/sortowana w pamięci – SQLite `LIKE` nie obsługuje polskich znaków bez wielkości liter, a skala lokalnego inwentarza (do kilkudziesięciu tysięcy) na to pozwala. |
| 2026‑11‑19 | „Nieobecne” tylko wtedy, gdy skan obejmował adres urządzenia; wyszukiwanie mapuje ł → l (ł nie ma w Unicode znaku łączonego, więc zwykłe pomijanie diakrytyków go nie obejmuje) – wykryte testem. |
| 2026‑11‑19 | Interfejs WWW urządzenia lub serwer wydruku (np. CUPS) opisywany neutralnie; ostrzeżenie tylko dla paneli administracyjnych, DevOps i stron logowania. |
| 2026‑11‑19 | Połączenia zamykane FIN zamiast RST (`SO_LINGER 0`). Zmierzone na routerze TP‑Link TL‑WR841N v9: jedno połączenie zerwane RST tuż po nawiązaniu wyłączało jego serwer UPnP na ~18 s (powtarzalnie, 2/2), a przekierowanie na porcie 80 przestało odpowiadać na ponad 10 minut; zamknięcie FIN – 0 awarii (2/2). Samo tempo nie było przyczyną (90 zamkniętych portów przy 20/s – 0 awarii). TIME_WAIT powstaje tylko dla otwartych portów, więc jest nieistotny. |
| 2026‑11‑19 | Limit połączeń na pojedynczy host (`MaxConcurrentConnectionsPerHost` 10, `ConnectionsPerSecondPerHost` 20) obok limitu globalnego – tanie urządzenia nie dostają serii setek połączeń naraz. Skan Standardowy jednego hosta trwa przez to ~19 s. |
| 2026‑11‑19 | Odpowiedź HTTP wysłana przez serwer przed żądaniem (z dopełnieniem NUL) rozpoznawana jako HTTP (`http-banner`); realm `WWW-Authenticate` uwzględniany przy rozpoznawaniu panelu; panel za 401 opisywany jako „wymaga logowania”, a HTTP Basic bez TLS oznaczany jako przesyłanie hasła jawnym tekstem. Treść bez deklaracji kodowania, będąca poprawnym UTF‑8, dekodowana jako UTF‑8. |
| 2026‑11‑19 | Porównanie obserwacji uwzględnia listę portów sprawdzonych przez skan – wcześniej skan profilem Mobilnym po Standardowym raportował porty 81/1900/49152 routera jako zamknięte, a następny Standardowy jako nowe (wykryte na prawdziwej sieci). |
| 2026‑11‑19 | Zakładka „Aktywne” pokazuje też urządzenia nowe – po pierwszym skanie była pusta (zgłoszone przez użytkownika). |
| 2026‑11‑19 | Sieć skanu identyfikowana adresem MAC bramy: skan sieci przewodowej 192.168.0.0/24 oznaczał 12 urządzeń z domowej sieci 192.168.0.0/24 jako nieobecne. Komputer z WELES widziany przez Wi‑Fi i kabel występował jako dwa zasoby – teraz jeden. |
| 2026‑11‑19 | Segment sieci identyfikowany przez CIDR **i** MAC bramy; lista domyślnie pokazuje bieżącą sieć (ukrywa tylko inne rozpoznane sieci, żeby nie gubić 127.0.0.1 ani podsieci za VPN – wykryte testem integracyjnym). |
| 2026‑11‑19 | Status „Nieznane” dla urządzeń sieci, którą opuszczono: po skanie sieci przewodowej 11 urządzeń z sieci domowej było „Aktywnych”, choć nikt ich od dnia nie sprawdzał (zgłoszone przez użytkownika). |
| 2026‑11‑19 | Etap 4: dane podatności w głównej bazie SQLite (tabele z Etapu 1), snapshot jako zasób osadzony – jeden plik do wydania, import ~5 s. Zakres snapshotu = produkty, które WELES potrafi rozpoznać (ok. 5 tys. CVE zamiast 300 tys.), więc baza ma 1,1 MB. |
| 2026‑11‑19 | Aktualizacja z Internetu tylko na kliknięcie i tylko ze stałą listą produktów – zapytania o wykryte wersje/modele ujawniałyby zawartość sieci użytkownika. |
| 2026‑11‑19 | Jedno `AssetVulnerability` na (urządzenie, CVE) zamiast na usługę z danego skanu – każdy skan tworzy nowe `DiscoveredService`, więc stary indeks powielałby dopasowania. Migracja usuwa ewentualne duplikaty. |
| 2026‑11‑19 | Dokładne porównanie wersji: test wykazał, że tolerowanie sufiksu (`9.3` ≈ `9.3p2`) oznaczało naprawioną wersję OpenSSH jako podatną. |
| 2026‑11‑19 | Model sprzętu bez wersji firmware → „Brak wystarczających danych”, a nie brak wyniku: dla routera to najcenniejsza wskazówka (sprawdź firmware), ale nie jest liczona jako otwarta podatność. |
| 2026‑11‑19 | Laboratorium demo (`deploy/demo-lab`): prawdziwe stare obrazy usług tylko na 127.0.0.11–15 zamiast symulowanych banerów – symulacja byłaby udawaniem wyników. Nieuruchomione lokalnie (brak Dockera). |
| 2026‑11‑19 | Dwa języki interfejsu (zgłoszone przez użytkownika: „część po polsku, część po angielsku”). Polskie teksty są kluczami słownika, a komunikaty zapisane w bazie tłumaczone przy wyświetlaniu wzorcami – zapisywanie kluczy zamiast tekstów wymagałoby migracji danych i zmiany każdego producenta komunikatów. Nazwy modułów w trybie polskim też po polsku (Pulpit, Urządzenia, Podatności…). |
| 2026‑11‑19 | Dopasowania: wpis NVD bez zakresu wersji („wszystkie wersje”) → „Brak wystarczających danych”; warunek NVD wskazujący inną dystrybucję niż baner (CVE-2008-3844 – tylko pakiety Red Hata) → brak dopasowania. Wykryte na Raspberry Pi użytkownika (OpenSSH 8.4p1 Debian). |
| 2026‑11‑19 | Etap 5: ocena addytywna z jawnymi składnikami zamiast modelu statystycznego – każdy punkt da się pokazać użytkownikowi („Nie ukrywaj powodów”). CVE grupowane po produkcie i porcie, bo jedna aktualizacja usuwa je razem; Security Posture Score liczony z najgorszego urządzenia i pięciu najgorszych, żeby jedno bardzo słabe urządzenie było widoczne. |
| 2026‑11‑19 | Reguła panelu administracyjnego obniżona do „dostępny w sieci” (40): na kopii bazy router domowy dostał 78 pkt za stronę startową bez uwierzytelnienia HTTP, a TP-Link loguje formularzem – skan nie dowodzi dostępu bez hasła. |
| 2026‑11‑19 | Dostępność z Internetu: tylko adres publiczny podnosi ocenę; dla sieci lokalnej czynnik jest pokazany jako „nie badano” (0 pkt) – bez zgadywania przekierowań portów (zewnętrzna powierzchnia ataku to Etap 8). |
| 2026‑11‑19 | Jedno urządzenie z kilkoma interfejsami: skaner odczytuje klucz hosta SSH (`SshHostKeyProbe` – identyfikacja, KEXINIT, ECDH nistp256 lub DH group14, bez logowania) i `ScanResultWriter` łączy urządzenia o tym samym kluczu w najstarszy rekord (pola użytkownika, obserwacje, podatności, problemy i oceny przenoszone). Ochrona przed kluczami wspólnymi dla całej serii urządzeń: łączenie tylko przy tym samym prefiksie OUI. Bez łączenia po „podobnym” MAC. Zweryfikowane na Raspberry Pi użytkownika (kabel …:b8 i Wi‑Fi …:b9, ten sam klucz ED25519 co `ssh-keyscan`): dwa rekordy scalone w jeden. |
