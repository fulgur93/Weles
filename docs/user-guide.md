# Przewodnik użytkownika

## Uruchomienie

Po uruchomieniu WELES otwiera panel w domyślnej przeglądarce. Jeśli przeglądarka się nie otworzyła, skopiuj adres
wypisany w konsoli (`WELES: http://127.0.0.1:5080/auth?token=…`). Ponowne uruchomienie programu, gdy WELES już działa,
otwiera istniejącą sesję zamiast startować drugi serwer.

## Nawigacja

| Sekcja | Przeznaczenie | Dostępność |
|--------|---------------|------------|
| Dashboard | Security Posture Score, urządzenia, usługi, podatności, ostatni skan, status AI | Etap 1 (dane po pierwszym skanie) |
| Assets | inwentarz urządzeń, status obecności, historia zmian, nazwy i krytyczność | ✅ Etap 3 |
| Network Discovery / Scans | zakresy, wykrywanie urządzeń, porty, usługi, historia skanów | ✅ Etap 2 |
| Attack Surface | domeny, DNS, certyfikaty, usługi publiczne | Etap 8 |
| Vulnerabilities | dopasowania CVE (NVD, KEV, EPSS), lokalna baza i jej aktualizacja | ✅ Etap 4 |
| Risk Assessment | ocena ryzyka z uzasadnieniem | Etap 5 |
| Network Topology / Attack Paths / Monitoring | mapa, ścieżki ekspozycji, zmiany w czasie | Etap 7 |
| AI Analyst | lokalny asystent bezpieczeństwa | Etap 6 |
| Reports | PDF, eksport/import audytu | Etap 9 |
| Agents | zdalne agenty | Etap 10 |
| Settings | wersja, ścieżki, baza, AI, motyw, pobieranie logów | Etap 1 |

Moduły jeszcze niezaimplementowane są oznaczone w menu numerem etapu (np. `E4`) i otwierają opis planowanego zakresu –
nie pokazują pustych ani pozornie działających ekranów.

## Pierwszy audyt (Network Discovery)

1. **Network Discovery → Sieci tego komputera** – WELES pokazuje wykryte interfejsy, sieci i bramy. Przycisk
   „Utwórz zakres …” wypełnia formularz siecią lokalną (duże sieci są zawężane do /24 wokół Twojego adresu).
2. **Zakres** – wpisz adresy (IP, CIDR do /16, zakres `10.0.0.10-50`, domena) oraz wykluczenia. „Podgląd zakresu”
   pokazuje, ile adresów zostanie sprawdzonych. Adresy publiczne wymagają osobnej zgody.
3. **Zatwierdź…** – potwierdź, że masz uprawnienia do zasobów. Każda edycja zakresu cofa zatwierdzenie.
4. Wybierz profil portów: *Szybki* (39 portów), *Standardowy* (~130), *Urządzenia mobilne* (szybki + ADB, FTP aplikacji
   do udostępniania plików, AirDroid, KDE Connect, iPhone) albo własną listę (`22,80,8000-8100`) i **Uruchom skan**.
   Niezależnie od profilu WELES pyta sieć lokalną przez mDNS, jakie usługi ogłaszają urządzenia (np. Chromecast,
   drukarki, debugowanie bezprzewodowe Androida) – ogłoszone porty są skanowane zawsze.
5. Strona skanu pokazuje postęp na żywo (fazy, hosty, porty, usługi) i przycisk **Zatrzymaj skan** – zebrane wyniki zostają zapisane.
6. Kliknij host, aby zobaczyć usługi: produkt i wersję, **pewność identyfikacji** i metodę (baner, HTTP, TLS…),
   tytuł strony, wykryte panele administracyjne, certyfikat TLS (ważność, wystawca, zgodność nazwy), brakujące nagłówki
   bezpieczeństwa, uwierzytelnianie Redis, warstwę bezpieczeństwa RDP (NLA).

„Dlaczego taki typ urządzenia?” – pod rozwiniętym hostem widać listę powodów klasyfikacji.
Wersja z dopiskiem dystrybucji (np. Ubuntu) może zawierać poprawki bezpieczeństwa bez zmiany numeru – WELES to zaznacza.

Limity (równoległość, tempo, timeouty, maks. liczba hostów) są w `appsettings.json`, sekcja `Weles:Scanning`.

## Inwentarz urządzeń (Assets)

- **Wyszukiwanie** – kilka słów naraz (wszystkie muszą pasować): nazwa, IP, MAC, producent, system, produkt
  (np. `openssh`), numer otwartego portu (np. `3389`). Wielkość liter i polskie znaki nie mają znaczenia (`lodz` = `Łódź`).
- **Filtry** – status, typ, segment, system, „z otwartymi portami”; liczby przy filtrach pokazują, ile urządzeń zostanie.
- **Sortowanie** – klik w nagłówek; **Shift+klik** dodaje kolejny poziom (np. porty ↓, potem nazwa ↑).
- **Kolumny** – przycisk „Kolumny”; wybór jest zapamiętywany.
- **Status**: *Aktywne* – wykryte w ostatnim skanie obejmującym jego adres (w tym *Nowe* – wykryte po raz pierwszy);
  *Nieobecne* – skan obejmował adres, ale urządzenia nie znalazł; *Poza ostatnimi skanami* – żaden ostatni skan nie
  sprawdzał tego adresu; *Nieznane* – urządzenie sprawdzono ostatnio w jego sieci, ale potem skanowano inną sieć, więc
  jego obecny stan nie jest znany (zmieni się po skanie jego sieci). Liczą się tylko skany **tej samej sieci**
  (rozpoznawanej po adresie MAC routera): skan biura 192.168.0.0/24 nie czyni urządzeń z domowej sieci 192.168.0.0/24
  „nieobecnymi”, tylko „nieznanymi”.
- **Sieć** – lista domyślnie pokazuje urządzenia sieci, do której komputer jest teraz podłączony (rozpoznawanej po
  zakresie adresów i adresie MAC routera); urządzenia z innych sieci są ukryte z informacją, ile ich jest. Filtr
  „Wszystkie sieci” lub wybór konkretnej sieci pokazuje resztę. Kolumna „Sieć” podaje np.
  „192.168.0.0/24 · TP-LINK c0:4a:00:ee:19:4a”.
- **Ten komputer** występuje raz, nawet jeśli łączył się raz przez Wi‑Fi, a raz kablem.
- **Porty** – profil Szybki sprawdza mniej portów niż Standardowy; porty, których ostatni skan nie sprawdzał, zostają
  pokazane z wcześniejszej obserwacji i nie są uznawane za zamknięte.
- **Szczegóły urządzenia** – tożsamość, uzasadnienie klasyfikacji, aktualne usługi, oś czasu obserwacji ze zmianami
  (porty, wersje, certyfikaty, adres IP) i nieobecnościami.
- **Edytuj** – własna nazwa (np. „Telefon Xiaomi”), typ, krytyczność dla organizacji (użyta w ocenie ryzyka) i notatki.
  Skany nie nadpisują tych pól.

## Podatności (Vulnerabilities)

- **Lokalna baza** – przy pierwszym uruchomieniu WELES importuje dołączoną bazę (NVD, CISA KEV, EPSS dla produktów,
  które rozpoznaje). Działa bez Internetu; karta na górze pokazuje datę danych każdego źródła.
- **Aktualizuj z Internetu** – pobiera zmiany z NVD (przyrostowo), pełny katalog KEV i aktualne wyniki EPSS; można
  przerwać. Wysyłana jest tylko stała lista produktów WELES – nic o Twojej sieci.
- **Dopasowanie** odbywa się po każdym skanie i po każdej aktualizacji bazy – do aktualnych usług urządzenia (z wersją
  z banera lub protokołu) i do modelu urządzenia. Usługa bez wersji nie daje dopasowania.
- **Status dopasowania**:
  *Potwierdzone* – producent, produkt i dokładna wersja (pewne rozpoznanie ≥ 90%) w zakresie NVD;
  *Prawdopodobne* – rozpoznanie 70–89% albo NVD wymaga dodatkowego warunku (np. systemu);
  *Wymaga weryfikacji* – pakiet dystrybucji (Ubuntu, Debian… – poprawki mogą być przeniesione bez zmiany wersji),
  wersja niedokładna (np. `2.4` wobec granicy `2.4.52`) albo pewność rozpoznania < 70%;
  *Brak wystarczających danych* – model urządzenia (np. router TP-Link) jest w NVD, ale wersji firmware skan nie zna –
  sprawdź ją w panelu urządzenia.
  Każde dopasowanie ma uzasadnienie (najedź na wiersz) i procent pewności.
- **Status podatności**: *Otwarte*; *Rozwiązane* – kolejny skan nie potwierdził dowodu (np. nowsza wersja);
  *Zaakceptowane* – świadoma decyzja w szczegółach CVE (przycisk „Akceptuj ryzyko”), zachowywana przez kolejne skany.
- **Szczegóły CVE** – opis z NVD, CVSS, EPSS, obecność w CISA KEV, podatne zakresy wersji, referencje i lista urządzeń.

## Telefony i tablety

WELES sprawdza, co telefon **wystawia w sieci**: otwarte porty, ADB przez sieć (z autoryzacją lub bez), debugowanie
bezprzewodowe (wykrywane przez mDNS), serwery udostępniania plików. Telefony zwykle mają losowy adres MAC, więc
producent nie jest znany. Wersji Androida/iOS i poprawek bezpieczeństwa nie da się odczytać z sieci.
Aby przetestować wykrywanie, włącz na telefonie *Opcje programisty → Debugowanie bezprzewodowe* i uruchom skan.

## Motyw

Domyślny jest ciemny. Przełącznik w prawym górnym rogu lub w Settings → Wygląd. Wybór zapisywany jest w bazie.

## Laboratorium demonstracyjne

`deploy/demo-lab` (Docker Compose) uruchamia prawdziwe, stare wersje usług wyłącznie na adresach 127.0.0.11–15.
Skan tego zakresu z profilem Szybki pokazuje wykrywanie usług i dopasowania CVE bez skanowania sieci na sali
(szczegóły w `deploy/demo-lab/README.md`).

## Tryb demonstracyjny

`--demo` uruchamia WELES z osobną bazą (`weles-demo.db`) i wyraźnym paskiem „TRYB DEMONSTRACYJNY”.
Dane demonstracyjne nigdy nie trafiają do bazy z rzeczywistymi wynikami.

## Logi

Settings → Dane i logi → **Pobierz logi (ZIP)**. Logi rotują codziennie (maks. 10 MB na plik, 14 plików).
