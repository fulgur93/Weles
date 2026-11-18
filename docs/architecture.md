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
| `Vulnerability` | `CveId` (unikalny), `Title`, `Description`, `CvssScore`, `CvssVector`, `CvssVersion`, `Severity`, `EpssScore`, `EpssPercentile`, `IsKnownExploited`, `KevDateAdded`, `Source`, `PublishedAt`, `LastModifiedAt`, `ReferencesJson` | 1‑N `VulnerabilityAffectedProduct` |
| `VulnerabilityAffectedProduct` | `Vendor`, `Product`, `Cpe`, `VersionStartIncluding/Excluding`, `VersionEndIncluding/Excluding` | FK Cascade, indeks `(Vendor, Product)` |
| `AssetVulnerability` | `MatchStatus` (Potwierdzone/Prawdopodobne/Wymaga weryfikacji/Brak danych), `MatchConfidence`, `MatchReason`, `Status` (Open/Resolved/Accepted), `FirstDetectedAt`, `LastDetectedAt` | FK `Asset`, `Vulnerability`, opcjonalnie `DiscoveredService` i `Scan`; unikalny `(AssetId, VulnerabilityId, DiscoveredServiceId)` |
| `RiskFinding` | `RuleId`, `Title`, `Description`, `Category`, `Level`, `Score`, `Evidence`, `Recommendation` | FK `Scan` (Cascade), `Asset` (Cascade) |
| `RiskScore` | `Score`, `Level`, `BreakdownJson`, `CalculatedAt` | FK `Scan` (Cascade), `Asset` opcjonalny (null = Security Posture Score całej infrastruktury) |

### 4.3. Encje kolejnych etapów (zaprojektowane, dodawane migracją w swoim etapie)

| Encja | Etap | Zarys |
|-------|------|-------|
| `NetworkInterface` | 3 | `AssetId`, `MacAddress`, `IpAddress`, `Name` – urządzenia z wieloma adresami (przesunięte z Etapu 2: korelacja MAC/IP w `Asset` wystarcza do discovery) |
| `SoftwareVersion` | 4 | znormalizowany katalog `(Vendor, Product, Version, Cpe)` współdzielony przez usługi; do tego czasu pola leżą w `DiscoveredService` |
| `NetworkRelationship` | 7 | `SourceAssetId`, `TargetAssetId`, `Kind` (same‑segment, gateway, reachable‑service), `Evidence`, `Confidence`, `ScanId` |
| `AttackPath` + `AttackPathStep` | 7 | uporządkowane kroki z `Justification` i `Confidence`, `IsHypothetical = true` zawsze, dopóki nie ma dowodu |
| `Domain` | 8 | nazwa, rodzaj (apex/sub), źródło (DNS, CT), rekordy DNS jako JSON, FK `ScanTarget` |
| `AuditReport` | 9 | `ScanId`, `Format`, `FilePath`, `Sha256`, `CreatedAt`, `AiSummary` |
| `AIConversation`, `AIMessage` | 6 | rozmowy + wiadomości (`Role`, `Content`, `ContextSnapshotJson`, `Model`, `TokensIn/Out`) |
| `Agent`, `AgentScan` | 10 | `Name`, `TokenHash` (nigdy jawny token), `Status`, `LastSeenAt`, `RevokedAt`, dozwolone zakresy |

### 4.4. Zmiany w Etapie 2 (migracja `Stage2Discovery`)

- `ScanEvent` – dziennik skanu (start, fazy, ostrzeżenia, zatrzymanie, błędy), kaskadowo z `Scan`.
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
| Porty | TCP connect, `ConnectionGate` = limit równoległości + token bucket (połączenia/s), zamknięcie RST (bez TIME_WAIT) | brak |
| Usługi | baner pasywny → sondy protokołów tylko na ich portach (Redis `PING`/`INFO server`, PostgreSQL `SSLRequest`, RDP X.224 z wykrywaniem NLA) → `GET /` → TLS (certyfikat, protokół, szyfr, próba TLS 1.0/1.1) → HTTP po TLS | brak |
| Producent | Rejestr IEEE MA-L osadzony w aplikacji (`oui.csv.gz`, ~26,5 tys. wpisów, odświeżanie `deploy/tools/update-oui.sh`) + prefiksy wirtualizacji; MAC losowe/lokalne oznaczane | – |
| Klasyfikacja | `AssetClassifier` – typ i system z listą powodów (banery, porty, TTL, producent, brama, interfejs WWW) | – |

Zasady rozpoznawania:
- **Numer portu nigdy nie daje produktu ani wersji** (`port-hint`, pewność ≤ 25).
- Pewność: baner/protokół z wersją 90–95, produkt bez wersji 70–85, rozpoznany protokół 60–70, nierozpoznany baner 25.
- CPE tworzony tylko przy znanym produkcie **i** wersji (`8.9p1` → `8.9:p1` jak w NVD).
- Sufiks dystrybucji (`Ubuntu-3ubuntu0.10`, `+deb12u3`, `(Ubuntu)`) zapisywany jako `distribution` – podstawa statusu „Wymaga weryfikacji” w Etapie 4.
- Brak udanego handshake TLS 1.0/1.1 jest **niejednoznaczny** (polityka OpenSSL klienta) – raportowana jest tylko potwierdzona akceptacja.

Ograniczenia znane po Etapie 2: brak UDP (SNMP, mDNS, NetBIOS-NS), brak SMB negotiate (wersja SMB/SMBv1 – Etap 5), brak STARTTLS dla SMTP/IMAP, MongoDB rozpoznawane tylko z portu.

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
| 2 | Network Discovery: interfejsy, CIDR, zakresy z zatwierdzaniem, ICMP/TCP/ARP, porty, banery, TLS, HTTP, zapis do bazy, postęp na żywo, zatrzymanie | ✅ (laboratorium demo → Etap 4) |
| 3 | Assets: tabela (szukanie, sortowanie, filtry, paginacja, kolumny), szczegóły, historia | ✅ |
| 4 | Vulnerability Intelligence: NVD/KEV/EPSS, snapshot offline, matcher wersji ze statusami | ✅ |
| 5 | Risk Engine: reguły, scoring z wyjaśnieniem, Security Posture Score, trend | ✅ |
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
