# WELES – Attack Surface Intelligence Platform

**W**atchful **E**nterprise **L**ocal **E**nvironment **S**ecurity – lokalna platforma do identyfikowania, analizowania
i monitorowania powierzchni ataku infrastruktury IT. Projekt na HackNation 2026 (zadanie *Attack Surface Intelligence*).

- Samodzielna aplikacja (.NET 10 self-contained, SQLite) – bez instalowania runtime’u, baz danych ani modeli.
- Panel Blazor dostępny wyłącznie na `127.0.0.1`, chroniony tokenem sesji.
- Lokalne AI (Ollama + model Q4 dołączone do paczki) – dane infrastruktury nie opuszczają komputera.

## Szybki start (deweloper)

```bash
dotnet run --project src/Weles.App            # otwiera przeglądarkę z http://127.0.0.1:5080
dotnet run --project src/Weles.App -- --demo  # osobna baza demonstracyjna
dotnet test
deploy/tools/update-vulndb.sh                 # odświeża dołączoną bazę podatności (NVD, KEV, EPSS)
deploy/tools/fetch-ai-runtime.sh              # Ollama + model do artifacts/ai-runtime (lokalne AI, ~2,5 GB)
```

Przełączniki: `--port N`, `--data-dir PATH`, `--demo`, `--no-browser`.

## Paczki

```bash
deploy/linux/publish.sh linux-x64            # artifacts/weles-<ver>-linux-x64.tar.gz
pwsh deploy/windows/publish.ps1 -Rid win-x64 # artifacts/weles-<ver>-win-x64.zip
```

## Dokumentacja

- [Architektura, ryzyka, model danych, plan etapów](docs/architecture.md)
- [Instalacja](docs/installation.md)
- [Przewodnik użytkownika](docs/user-guide.md)
- [Instrukcja dla sprawdzających](docs/instrukcja-dla-sprawdzajacych.md) · [wersja TXT](docs/instrukcja-dla-sprawdzajacych.txt)
- [Bezpieczeństwo](docs/security.md)
- [Scenariusz demonstracji](docs/demo.md)

## Status

| Etap | Zakres | Status |
|------|--------|--------|
| 1 | Fundament: solution, Blazor, EF Core + SQLite, logowanie, bezpieczny hosting, layout | ✅ |
| 2 | Network Discovery: zakresy z zatwierdzaniem, ICMP/TCP/ARP, porty, banery, HTTP, TLS, klasyfikacja, historia, postęp na żywo | ✅ |
| 3 | Assets: inwentarz z wyszukiwaniem, filtrami, sortowaniem, historią zmian i polami ręcznymi | ✅ |
| 4 | Vulnerability Intelligence: lokalna baza NVD/KEV/EPSS działająca offline, aktualizacja na żądanie, dopasowanie wersji ze statusami i uzasadnieniem, laboratorium demo | ✅ |
| 5 | Risk Engine: reguły konfiguracji z MITRE ATT&CK, ocena urządzeń z uzasadnieniem, Security Posture Score z trendem, priorytety napraw | ✅ |
| 6 | AI Security Analyst: dołączona Ollama + Qwen3‑4B Q4 jako proces potomny, czat ze strumieniowaniem, kontekst wyłącznie z bazy WELES | ✅ |
| 7 | Monitoring (porównanie skanów, zmiany w czasie, harmonogram tylko w zatwierdzonej sieci), topologia SVG, ścieżki ataku jako hipotezy | ✅ |
| 8 | External Attack Surface: DNS, SPF/DMARC, subdomeny z CT, certyfikaty, usługi publiczne (pasywnie lub przez zatwierdzony zakres) | ✅ |
| 9 | Raporty: PDF, eksport JSON/ZIP z SHA‑256, import audytu z walidacją, podsumowanie AI audytu | ✅ |
| 10 | Agenci: Worker Service Windows/Linux, wychodzące HTTPS z przypiętym certyfikatem, rejestracja, unieważnianie, tylko zatwierdzone zakresy | ✅ |
| 11 | Pakowanie: instalator Windows (bez administratora), paczka DEB, autostart, dołączona Ollama i model | ✅ |

## Rozszerzenie: wyzwanie AGH (HackNation 2026)

Fingerprinting HTTP/HTTPS z sygnaturami (wbudowane i własne), import celów i wyników (nmap XML, CSV, JSON), eksport CSV/JSON,
integracja z DefectDojo (CVE, CWE, CVSS, EPSS, granularność, reimport), RBAC z 4 rolami, szyfrowanie bazy SQLCipher,
opcjonalny silnik nmap (porty i wersje, bez skryptów NSE), zakresy do 65 536 adresów skanowane podgrupami z pomiarem tempa, okna czasowe z wstrzymaniem i wznowieniem, obsługa hostów
niestabilnych (próg kolejnych braków, zależność od pory dnia), opcjonalny dostęp do panelu z sieci lokalnej (HTTPS,
logowanie). Szczegóły: `docs/architecture.md` §5i.
