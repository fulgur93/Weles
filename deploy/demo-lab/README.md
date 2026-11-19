# Laboratorium demonstracyjne WELES

Prawdziwe, celowo stare wersje usług uruchomione w Dockerze i dostępne **tylko na adresach pętli zwrotnej**
(127.0.0.11–127.0.0.15). Pozwala pokazać wykrywanie usług i dopasowanie podatności, gdy na sali nie ma sieci
albo nie ma zgody na jej skanowanie. Wyniki nie są udawane – WELES skanuje rzeczywiste procesy.

| Adres | Usługa | Przykładowe dopasowania |
|-------|--------|-------------------------|
| 127.0.0.11:80 | Apache httpd 2.4.49 | CVE-2021-41773 (CISA KEV), CVE-2021-42013 |
| 127.0.0.12:80 | nginx 1.18.0 | CVE-2021-23017 |
| 127.0.0.13:6379 | Redis 5.0.7 | CVE-2021-32626 i inne |
| 127.0.0.14:22 | OpenSSH 7.9p1 (Alpine) | CVE-2023-38408 i inne |
| 127.0.0.15:3306 | MySQL 5.7.30 | biuletyny Oracle CPU |

## Uruchomienie

```bash
cd deploy/demo-lab
docker compose up -d --build
```

W WELES: **Network Discovery → nowy zakres** `127.0.0.11-127.0.0.15`, zatwierdź, uruchom skan z profilem **Szybki**.
Po skanie dopasowania pojawią się w **Vulnerabilities** i w szczegółach każdego urządzenia.

Po pokazie: `docker compose down`.

## Bezpieczeństwo

- Porty są publikowane wyłącznie na 127.0.0.x – usługi nie są dostępne z sieci lokalnej.
- Brak danych i brak kont do zalogowania (MySQL z losowym hasłem root, SSH bez haseł i kluczy, Redis w trybie
  `protected-mode`).
- Nie uruchamiaj tych obrazów na adresach dostępnych z sieci – to podatne wersje.

> Status: pliki przygotowane, ale nieuruchomione na komputerze deweloperskim (brak Dockera). Pierwsze uruchomienie
> może wymagać korekty, np. wersji pakietu `openssh-server` w archiwum Alpine 3.9.
