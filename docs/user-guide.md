# Przewodnik użytkownika

## Uruchomienie

Po uruchomieniu WELES otwiera panel w domyślnej przeglądarce. Jeśli przeglądarka się nie otworzyła, skopiuj adres
wypisany w konsoli (`WELES: http://127.0.0.1:5080/auth?token=…`). Ponowne uruchomienie programu, gdy WELES już działa,
otwiera istniejącą sesję zamiast startować drugi serwer.

## Nawigacja

| Sekcja | Przeznaczenie | Dostępność |
|--------|---------------|------------|
| Dashboard | Security Posture Score, urządzenia, usługi, podatności, ostatni skan, status AI | Etap 1 (dane po pierwszym skanie) |
| Assets | inwentarz urządzeń i ich historia | Etap 3 |
| Network Discovery / Scans | zakresy, wykrywanie urządzeń, porty, usługi | Etap 2 |
| Attack Surface | domeny, DNS, certyfikaty, usługi publiczne | Etap 8 |
| Vulnerabilities | dopasowania CVE (NVD, KEV, EPSS) | Etap 4 |
| Risk Assessment | ocena ryzyka z uzasadnieniem | Etap 5 |
| Network Topology / Attack Paths / Monitoring | mapa, ścieżki ekspozycji, zmiany w czasie | Etap 7 |
| AI Analyst | lokalny asystent bezpieczeństwa | Etap 6 |
| Reports | PDF, eksport/import audytu | Etap 9 |
| Agents | zdalne agenty | Etap 10 |
| Settings | wersja, ścieżki, baza, AI, motyw, pobieranie logów | Etap 1 |

Moduły jeszcze niezaimplementowane są oznaczone w menu numerem etapu (np. `E4`) i otwierają opis planowanego zakresu –
nie pokazują pustych ani pozornie działających ekranów.

## Motyw

Domyślny jest ciemny. Przełącznik w prawym górnym rogu lub w Settings → Wygląd. Wybór zapisywany jest w bazie.

## Tryb demonstracyjny

`--demo` uruchamia WELES z osobną bazą (`weles-demo.db`) i wyraźnym paskiem „TRYB DEMONSTRACYJNY”.
Dane demonstracyjne nigdy nie trafiają do bazy z rzeczywistymi wynikami.

## Logi

Settings → Dane i logi → **Pobierz logi (ZIP)**. Logi rotują codziennie (maks. 10 MB na plik, 14 plików).
