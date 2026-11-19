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
| 6 | AI Security Analyst | ⏳ następny |
| 7–11 | Monitoring/Topology, External, Raporty, Agenci, Pakowanie | planowane |
