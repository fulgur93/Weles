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

## Agent (opcjonalnie)

Paczki agenta: `deploy/agent/publish-agent.sh linux-x64` lub `win-x64` (samodzielny plik, bez .NET na komputerze agenta).
Linux:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin weles-agent
sudo install -d -o weles-agent -g weles-agent -m 0700 /etc/weles-agent
sudo cp -r weles-agent-<wersja>-linux-x64 /opt/weles-agent
sudo -u weles-agent /opt/weles-agent/weles-agent enroll --config /etc/weles-agent/agent.json --server https://ADRES:PORT --pin ODCISK --code KOD
sudo cp /opt/weles-agent/weles-agent.service /etc/systemd/system/ && sudo systemctl enable --now weles-agent
```

Windows (PowerShell jako administrator, w rozpakowanym katalogu): `.\install-agent.ps1 -Server https://ADRES:PORT -Pin ODCISK -Code KOD`.
Polecenie z adresem, odciskiem i kodem pokazuje strona **Agenci**.

## Odinstalowanie

Usuń katalog programu. Aby usunąć również wyniki audytów, usuń katalog danych.

## Budowanie paczek

Wymaga .NET SDK 10 (tylko na maszynie budującej):

```bash
deploy/linux/publish.sh linux-x64
pwsh deploy/windows/publish.ps1 -Rid win-x64
```

Instalatory (Inno Setup / AppImage + DEB) oraz dołączanie Ollamy i modelu – Etap 11, opis w `architecture.md` §3.2.
