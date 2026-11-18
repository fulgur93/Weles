# Instalacja

## Wymagania

- Windows 10/11 x64 lub Linux x64 (glibc 2.31+, np. Ubuntu 20.04+, Debian 11+, Fedora 36+).
- Nie są wymagane: .NET Runtime, serwer bazy danych, Python, Ollama ani dostęp do Internetu.
- Lokalne AI (od Etapu 6): ok. 4 GB wolnej pamięci RAM i ok. 4 GB miejsca na dysku. GPU opcjonalne.

## Windows (ZIP – wersja demonstracyjna)

1. Rozpakuj `weles-<wersja>-win-x64.zip` do dowolnego katalogu (np. `C:\Programy\WELES`).
2. Uruchom `WELES.cmd`. Otworzy się przeglądarka z panelem.

## Linux (TAR.GZ – wersja demonstracyjna)

```bash
tar -xzf weles-<wersja>-linux-x64.tar.gz -C ~/opt
~/opt/weles-<wersja>-linux-x64/weles
```

## Gdzie są dane

| System | Katalog danych |
|--------|----------------|
| Windows | `%LOCALAPPDATA%\Weles` |
| Linux | `$XDG_DATA_HOME/weles` (domyślnie `~/.local/share/weles`) |

Podkatalogi: `data/` (baza SQLite), `logs/`, `config/`, `reports/`, `exports/`, `vulndb/`, `keys/`.
Katalog tworzony jest automatycznie przy pierwszym uruchomieniu; na Linuksie z uprawnieniami `0700`.
Inną lokalizację można wskazać przełącznikiem `--data-dir` lub zmienną `WELES_DATA_DIR`.

## Port

Domyślnie `5080`. Jeżeli jest zajęty, WELES automatycznie wybiera wolny port i wypisuje adres w konsoli.
Port można zmienić przełącznikiem `--port`. Panel nasłuchuje wyłącznie na `127.0.0.1`.

## Odinstalowanie

Usuń katalog programu. Aby usunąć również wyniki audytów, usuń katalog danych.

## Budowanie paczek

Wymaga .NET SDK 10 (tylko na maszynie budującej):

```bash
deploy/linux/publish.sh linux-x64
pwsh deploy/windows/publish.ps1 -Rid win-x64
```

Instalatory (Inno Setup / AppImage + DEB) oraz dołączanie Ollamy i modelu – Etap 11, opis w `architecture.md` §3.2.
