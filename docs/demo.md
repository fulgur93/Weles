# Scenariusz demonstracji (≤ 2 min)

| Czas | Krok | Co pokazujemy |
|------|------|---------------|
| 0:00 | Uruchomienie `WELES.cmd` / `./weles` | Otwiera się panel, brak konfiguracji, ekran startowy bez fikcyjnych liczb |
| 0:10 | Network Discovery → wykryty segment → **Zatwierdź zakres** → Start | Zakres musi być zatwierdzony – element bezpieczeństwa |
| 0:25 | Postęp na żywo | Wykrywane hosty, porty, usługi z wersjami i poziomem pewności |
| 0:50 | Vulnerabilities | Dopasowania CVE ze statusem (Potwierdzone / Wymaga weryfikacji), KEV, EPSS |
| 1:05 | Dashboard | Security Posture Score, krytyczne problemy, trend |
| 1:15 | Risk Assessment → urządzenie | „Dlaczego Critical?” – rozbicie punktacji |
| 1:30 | AI Analyst: „Jakie są trzy największe zagrożenia w mojej sieci?” | Odpowiedź offline oparta na danych z bazy, z identyfikatorami CVE i urządzeń |
| 1:50 | Rekomendacje + raport PDF | Priorytety napraw |

## Środowisko awaryjne (brak sieci na sali)

1. **Laboratorium lokalne** (`deploy/demo-lab`, Etap 2/4): Docker Compose z kontenerami o celowo starych wersjach usług
   (np. OpenSSH, nginx, Samba, Redis bez hasła) w izolowanej sieci bridge. Skan tej sieci daje **prawdziwe** wyniki.
2. **Tryb demonstracyjny** (`--demo`): osobna baza z jawnie oznaczonymi danymi przykładowymi i stałym paskiem
   „TRYB DEMONSTRACYJNY”. Nie udaje rzeczywistego skanu.

Przed prezentacją: uruchomić WELES raz, aby model AI był „rozgrzany” (pierwsza odpowiedź na CPU jest najwolniejsza).
