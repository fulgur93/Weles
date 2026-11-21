# Instalacja

## Wymagania

- Windows 10/11 x64 lub Linux x64 (glibc 2.31+, np. Ubuntu 20.04+, Debian 11+, Fedora 36+).
- Nie są wymagane: .NET Runtime, serwer bazy danych, Python, Ollama ani dostęp do Internetu.
- Lokalne AI (od Etapu 6): ok. 4 GB wolnej pamięci RAM i ok. 4 GB miejsca na dysku. GPU opcjonalne.

## Windows – instalator

1. Uruchom `weles-setup-<wersja>-win-x64.exe`. Wersja z lokalnym AI składa się z pliku `.exe` i plików `-1.bin`, `-2.bin`
   (model ma 2,4 GB) – trzymaj je w jednym katalogu. Wersja `-noai` to jeden plik bez lokalnego AI.
2. Instalacja jest **dla bieżącego użytkownika, bez uprawnień administratora**, do `%LOCALAPPDATA%\Programs\WELES`.
   Opcje: skrót na pulpicie, uruchamianie po zalogowaniu.
3. Skróty w menu Start: **WELES** i **WELES – tryb demonstracyjny**. Panel otwiera się w przeglądarce (tylko 127.0.0.1).

Odinstalowanie: *Ustawienia → Aplikacje → WELES*. Usuwa program i wpis autostartu; wyniki audytów zostają
w `%LOCALAPPDATA%\Weles`.

## Linux – paczka DEB (Ubuntu 22.04+, Debian 12+)

```bash
sudo apt install ./weles_<wersja>_amd64.deb
weles                      # albo z menu: WELES / Tryb demonstracyjny
```

Program trafia do `/opt/weles` (tylko do odczytu), polecenie `weles` do `/usr/bin`, skrót do menu aplikacji. Paczka nie
tworzy usług ani użytkowników. Odinstalowanie: `sudo apt remove weles` – dane w `~/.local/share/weles` zostają.

## Linux – archiwum (inne dystrybucje)

```bash
tar --zstd -xf weles-<wersja>-linux-x64.tar.zst -C ~/opt
~/opt/weles-<wersja>-linux-x64/weles
```

## Uruchamianie po zalogowaniu

*Ustawienia → Uruchamianie* (albo opcja instalatora Windows). WELES startuje w tle bez otwierania przeglądarki; skrót
WELES otwiera panel działającej aplikacji. Tylko dla bieżącego użytkownika: Windows – wartość `WELES` w
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, Linux – `~/.config/autostart/weles.desktop`.
Tryb demonstracyjny nie uruchamia się automatycznie.

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
deploy/tools/fetch-ai-runtime.sh            # Ollama dla Linuksa + model (raz; wersja przypięta, SHA-256)
deploy/tools/fetch-ai-runtime-windows.sh    # Ollama dla Windows + ten sam model
deploy/linux/build-deb.sh                   # artifacts/weles_<wersja>_amd64.deb   (--without-ai: weles-noai)
deploy/linux/publish.sh                     # artifacts/weles-<wersja>-linux-x64.tar.zst
deploy/windows/build-installer.sh           # instalator Windows na Linuksie (Inno Setup pod Wine; --without-ai)
pwsh deploy/windows/publish.ps1             # na Windows (Inno Setup 6, jeśli zainstalowany)
deploy/agent/publish-agent.sh linux-x64     # agent (opcjonalnie)
```

`deploy/tools/fetch-innosetup.sh` instaluje Inno Setup 6.7.4 (SHA-256 przypięty) w prywatnym prefiksie Wine.
