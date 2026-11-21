# Instrukcja dla sprawdzających – WELES (Attack Surface Intelligence)

Dokument opisuje **aktualnie działający** prototyp. Kroki są oparte na kodzie i dokumentacji
repozytorium (`README.md`, `docs/user-guide.md`, `docs/demo.md`).

---

## 1. Czym jest WELES

Lokalna platforma do bezpiecznego discovery/attack-surface scaningu. Nie jest to skrypt
`nmap` ani nakładka na skaner zewnętrzny – WELES ma **własny silnik skanowania** w .NET:
wykrywa hosty (ICMP, TCP connect, ARP, mDNS), skanuje porty z limitami tempa, czyta banery,
analizuje HTTP/HTTPS i TLS, rozpoznaje technologie sygnaturami, zapisuje historię i pokazuje
zmiany między skanami. Dane zostają na komputerze (SQLite/SQLCipher); jedynym świadomym
wyjściem danych jest integracja z DefectDojo.

Najważniejsze cechy wg zadania AGH:

| Wymaganie | Gdzie w interfejsie |
|---|---|
| Import IP / CIDR / domen, wykluczenia, zatwierdzanie zakresu | **Wykrywanie sieci** → *Zakresy skanowania* |
| Duże zakresy (>10 000 IP), podgrupy, pomiar tempa | automatycznie powyżej 1024 adresów; postęp na stronie skanu |
| Okno czasowe, częstotliwość, wstrzymanie/wznowienie | **Wykrywanie sieci** → harmonogram zakresu; **Skany** → *Wstrzymaj / Wznów* |
| Hosty, usługi, wersje, pewność identyfikacji | **Skany** → szczegóły skanu → host |
| HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | **Usługi web** oraz szczegóły hosta |
| CMS, frameworki, IoT, panele admin, staging | **Usługi web** (sygnatury wbudowane i własne) |
| Porównanie skanów, zmiany, hosty niestabilne | **Monitorowanie**, **Urządzenia**, **Ocena ryzyka** |
| Własne sygnatury | **Sygnatury** |
| Import wyników nmap XML / CSV / JSON | **Skany** → *Import i eksport wyników* |
| Eksport JSON / CSV, raport PDF, audyt ZIP | **Skany**, **Raporty** |
| RBAC – 4 role | **Użytkownicy** |
| Szyfrowanie danych w spoczynku | automatycznie (SQLCipher), plik bazy + osobny klucz |
| DefectDojo | **Integracje** |

---

## 2. Uruchomienie

### Z repozytorium (wymagany .NET 10 SDK)

```bash
cd /home/fulgur/RiderProjects/Weles
/home/fulgur/.dotnet/dotnet run --project src/Weles.App
```

Otworzy się `http://127.0.0.1:5080` (dokładny adres z tokenem sesji WELES wypisuje konsola).
Przełączniki: `--port N`, `--data-dir PATH`, `--demo`, `--no-browser`.

### Gotowa paczka

Nie wymaga runtime’u ani bazy danych:

```bash
./weles              # Linux
WELES.cmd            # Windows
```

`--demo` uruchamia osobną bazę demonstracyjną z wyraźnym paskiem „TRYB DEMONSTRACYJNY” –
dane demo nie mieszają się z rzeczywistymi wynikami.

### Pierwsze uruchomienie

1. Wejdź na adres z konsoli. Przy pustej bazie pojawia się ekran **/setup**.
2. Utwórz konto administratora (nazwa, hasło, powtórzenie). Pierwsze konto **musi** mieć rolę
   *Administracja*; potem zalogowanie jest automatyczne.
3. Kolejne konta dodaje **Użytkownicy** (tylko administrator).

Panel domyślnie słucha tylko na `127.0.0.1`. Opcjonalny dostęp z sieci lokalnej (domyślny port
`5443`): **Ustawienia → Dostęp z sieci lokalnej** (administrator) → wybierz adres IP tego komputera
i port → zapisz → zrestartuj WELES. Adres: `https://<adres>:<port>`; przeglądarka ostrzeże o
samopodpisanym certyfikacie – porównaj odcisk SHA-256 z Ustawieniami. Dostęp wymaga logowania
i tej samej podsieci.

### Środowisko testowe bez sieci na sali

`deploy/demo-lab` (Docker Compose) uruchamia kontenery z celowo starymi usługami na adresach
`127.0.0.11–15`. Skan tego zakresu profilem *Szybki* daje prawdziwe wyniki i dopasowania CVE.
Szczegóły: `deploy/demo-lab/README.md`.

---

## 3. Scenariusz walidacji: dwa skany i zmiany

To najkrótsza droga do sprawdzenia większości kryteriów oceny.

### Krok 1 – zakres i pierwszy skan

1. **Wykrywanie sieci → Sieci tego komputera**. Wybierz wykryty segment i „Utwórz zakres …”
   albo wpisz własny zakres, np. `127.0.0.11-15` (demo-lab), IP, CIDR lub domenę.
   Adresy publiczne wymagają osobnej zgody.
2. Użyj **Podglądu zakresu** – pokazuje liczbę adresów i ewentualne błędy.
3. **Zatwierdź…** – potwierdź uprawnienia. Bez zatwierdzenia skan się nie uruchomi,
   a każda edycja zakresu cofa zatwierdzenie.
4. Wybierz profil portów: *Szybki* (~39), *Standardowy* (~130), *Urządzenia mobilne* lub własną
   listę (np. `22,80,8000-8100`), po czym kliknij **Uruchom skan**.
5. Strona skanu pokazuje postęp na żywo: fazę, hosty, porty, usługi, tempo i szacowany koniec.
   Skan działa w tle – można zamknąć kartę. **Zatrzymaj skan** zachowuje zebrane dane.
6. Wejdź w hosta, aby zobaczyć: usługi i wersje z **pewnością**, tytuł strony, nagłówki,
   ciasteczka, certyfikat TLS, panele administracyjne, środowiska testowe, uzasadnienie
   klasyfikacji urządzenia.

### Krok 2 – zmiana i drugi skan

1. W środowisku testowym zmień stan usługi (np. zatrzymaj kontener, zmień wersję/nagłówek)
   albo – jeśli testujesz import – przygotuj drugi plik wyników.
2. Uruchom ten sam zakres ponownie (skanów nie trzeba usuwać).
3. **Monitorowanie**: porównanie ostatniego skanu z poprzednim (można wybrać dowolne dwa) –
   nowe i znikające urządzenia, nowe/zamknięte porty, zmiany wersji, certyfikatów i podatności.
4. **Urządzenia → szczegóły**: oś czasu obserwacji i przyczyna zmiany statusu.
   Statusy: *Aktywne*, *Nowe*, *Niestabilne* (1–2 braki odpowiedzi), *Nieobecne* (3 kolejne
   braki), *Nieznane* (skanowano inną sieć). WELES rozpoznaje też zależność od pory dnia.
5. **Raporty**: raport PDF zawiera również zmiany od poprzedniego audytu tej sieci.

### Krok 3 – duży zakres i okno czasowe (opcjonalnie)

- Maksymalny zakres to **65 536 adresów** (`appsettings.json` → `Weles:Scanning:MaxHostsPerScan`).
  Powyżej 1024 adresów skan dzieli się na podgrupy dobierane do zmierzonego tempa.
- Na stronie skanu widać numer podgrupy, liczbę gotowych adresów i szacowany koniec;
  w dzienniku – tempo każdej podgrupy.
- **Wstrzymaj** kończy bieżącą podgrupę i zatrzymuje skan; **Wznów skan** kontynuuje od
  następnej (bez podwójnego skanowania); **Zakończ bez wznawiania** zostawia zebrane wyniki.
- Harmonogram: co godzinę / co 6 godzin / codziennie / co tydzień. Najpierw trzeba uruchomić
  zakres ręcznie – ustala on sieć (router). Skan automatyczny jest pomijany, gdy zakres nie jest
  zatwierdzony albo komputer jest w innej sieci (inny router).
- Okno czasowe, np. `22:00–06:00`: skany startują tylko w oknie; skan, który nie zdąży,
  zostaje wstrzymany i wznawia się sam w kolejnym oknie.

> Uwaga bezpieczeństwa: skan jest odrzucany, gdy komputer jest w innej sieci niż ta, w której
> zakres był ostatnio skanowany (porównanie adresu MAC bramy). Wymuszenie skanu jest możliwe,
> ale powód i ostrzeżenie zostają w dzienniku skanu, a pusty wynik jest opisany na stronie skanu.
> Jeśli w topologii nie widać starszych urządzeń, użyj przełącznika **Sieć → Wszystkie sieci**.

---

## 4. Import i eksport danych

### Import celów i wyników

- **Cele**: w formularzu zakresu można wczytać listę z pliku (IP, CIDR, przedziały, domeny).
- **Wyniki**: **Skany → Import i eksport wyników → Wybierz plik wyników**. Akceptowane:
  - `nmap -oX plik.xml` (XML),
  - CSV z kolumnami `ip, port, protocol, service, product, version, cpe, banner, hostname, mac`,
  - JSON w formacie eksportu WELES.
  
  Wyniki trafiają do historii jak zwykły skan – działają porównania, podatności, ryzyko i raporty.
  Import **nie wysyła żadnego ruchu**.

### Eksport

| Dane | Gdzie |
|---|---|
| Najnowszy stan urządzeń CSV / JSON | **Skany** → *Eksport CSV / Eksport JSON (najnowszy stan)* |
| Usługi web CSV / JSON | **Usługi web** |
| Pełny audyt: PDF, ZIP (`audit.json` + PDF + `manifest.json` z SHA-256) | **Raporty** lub **Skany → Raport audytu** |
| Plik do ręcznego importu w DefectDojo | `GET /api/export/defectdojo.json` (przycisk w **Integracje**) |

Import audytu ZIP/JSON z innego WELES: **Raporty → Import audytu**. Plik jest walidowany
(dozwolone pliki, sumy SHA-256, format, rozmiary); zaimportowany audyt jest tylko do odczytu
i nie miesza się z lokalnymi urządzeniami.

---

## 5. Własne sygnatury

**Sygnatury** → edytor JSON z szablonem, test na już zebranych danych, import i eksport.
Sygnatury wykrywają **obecność cech**, nie eksploatują podatności: nagłówek, nazwa ciasteczka,
hash favicony, fragment HTML, ścieżka `/login`, `/admin`, `/version` (bez logowania), wersja
w stopce, fingerprint CMS-a. Działają też na starszych skanach. Wyniki widać w **Usługi web**,
w ocenie „ciekawości” i – jeśli włączone – w eksporcie do DefectDojo.

---

## 6. Role i uprawnienia (RBAC)

| Rola | Uprawnienia |
|---|---|
| **Administracja** | wszystko: użytkownicy, ustawienia, agenci, integracje, zakresy, skany, edycja, eksport |
| **Dodawanie, usuwanie, modyfikacja** | dodawanie/usuwanie zakresów, sygnatur, importów, raportów i integracja DefectDojo; edycja i uruchamianie skanów |
| **Modyfikacja i odczyt** | edycja istniejących danych, uruchamianie/zatrzymywanie skanów, podgląd; **bez** dodawania i usuwania |
| **Odczyt** | przeglądanie wszystkich stron i eksportów; bez zmian i bez uruchamiania skanów |

Konta tworzy i role zmienia **Użytkownicy**. Sesja jest co request weryfikowana – zmiana roli,
hasła, wyłączenie lub usunięcie konta natychmiast kończy sesję. Nie można usunąć ani
degradować ostatniego administratora.

Dane ręczne (własna nazwa, typ, krytyczność, notatki) w **Urządzenia → Edytuj** nie są
nadpisywane przez kolejne skany.

---

## 7. Szyfrowanie danych w spoczynku

Baza to **SQLCipher** (zaszyfrowany SQLite). Plik `data/weles.db` bez `keys/database.key`
jest nieczytelny. Klucz API DefectDojo jest dodatkowo szyfrowany przez ASP.NET Core Data
Protection i zapisywany zaszyfrowany w bazie – nie trafia do logów.

> Przy przenoszeniu instalacji przenieś **bazę i katalog `keys` razem**. Utrata klucza oznacza
> utratę danych. Logi do pobrania: **Ustawienia → Dane i logi → Pobierz logi (ZIP)**.

---

## 8. DefectDojo – połączenie i wysyłanie wyników

Wymagane uprawnienia: rola **Administracja** albo **Dodawanie, usuwanie, modyfikacja**
(strona `/integrations` wymaga polityki *manage*).

### 8.1 Przygotowanie po stronie DefectDojo

1. Zaloguj się do swojej instancji DefectDojo.
2. W profilu użytkownika weź **API v2 Key** (token).
3. Zapisz adres instancji, np. `https://defectdojo.example.org`.
   `http://` jest dopuszczalne tylko dla `localhost`, prywatnych adresów IP i `.local`
   (instancja testowa, bo token idzie w nagłówku).

### 8.2 Konfiguracja w WELES

**Integracje → Połączenie z DefectDojo:**

| Pole | Co wpisać |
|---|---|
| Adres DefectDojo | `https://defectdojo.example.org` (bez loginu/hasła i bez `/` na końcu) |
| Klucz API (Token) | API v2 Key; pole jest maskowane, puste = „zostaw zapisany” |
| Typ produktu | domyślnie `WELES` (tworzony przy pierwszym wysłaniu) |
| Produkt | domyślnie `WELES` |
| Engagement | domyślnie `Attack Surface` |
| Tytuł testu | np. `WELES discovery` – **stały tytuł = ten sam test przy każdym wysłaniu** |
| Zamykaj znaleziska, których WELES już nie wykrywa | domyślnie włączone (`close_old_findings`) |
| Sprawdzaj certyfikat TLS | włączone; wyłącz tylko dla testowej instancji z samopodpisanym certyfikatem |

Naciśnij **Zapisz**, potem **Sprawdź połączenie** (komunikat „Połączono z DefectDojo …”).

### 8.3 Co wysyłać (granularność)

W tej samej sekcji wybierz:

- **Podatności CVE** – z CVE, CWE, CVSS, EPSS i CISA KEV; można ustawić najsłabszą akceptowaną
  pewność dopasowania (domyślnie *Wymaga weryfikacji*),
- **Problemy konfiguracji** – np. FTP bez szyfrowania (CWE-319),
- **Technologie, panele administracyjne i środowiska testowe z sygnatur**,
- **Każda otwarta usługa jako znalezisko informacyjne** (inwentarz; domyślnie wyłączone),
- **Ryzyka zaakceptowane w WELES** (jako nieaktywne; domyślnie wyłączone),
- **Minimalny poziom** (domyślnie `Info`),
- **Grupowanie**: jedno znalezisko na host i port **albo** jedno na problem z listą endpointów,
- **Sieć** (wszystkie / bieżąca / konkretna) i **Źródło** (najnowszy stan albo konkretny skan).

Użyj **Podglądu** – pokazuje liczbę znalezisk, rozkład po poziomach i rodzajach oraz liczbę
endpointów. Potem **Wyślij do DefectDojo**. Komunikat poda liczbę wysłanych znalezisk oraz
`test #…`.

Wysyłanie używa endpointu `reimport-scan` z typem **`Generic Findings Import`** i stałym
tytułem testu: każde kolejne wysłanie aktualizuje **ten sam test**, więc DefectDojo zamyka
znaleziska, których WELES już nie widzi. Dane wychodzą wyłącznie pod wskazany adres.

### 8.4 Wariant ręczny (bez tokenu)

1. W **Integracje** kliknij **Plik JSON (Generic Findings Import)** – pobierze
   `weles-defectdojo.json` z ostatnio zapisanymi ustawieniami granularności.
2. W DefectDojo: **Import Scan Results → Scan type: Generic Findings Import** → wskaż plik.
   Nadaj produkt/engagement/test zgodnie z przyjętą konwencją.

---

## 9. Sprawdzenie instalacji (opcjonalnie)

```bash
/home/fulgur/.dotnet/dotnet build src/Weles.App --nologo -v q
/home/fulgur/.dotnet/dotnet test --nologo -v q
```

Testy w środowisku bez uprawnień administratorskich mogą zgłosić jeden niezwiązany z
funkcjonalnością przypadek `Icmp_ping_of_loopback_works_without_administrator_rights`
(wymaga surowych socketów ICMP). Pozostałe testy przechodzą.

---

## 10. Najczęstsze pułapki

| Objaw | Wyjaśnienie / działanie |
|---|---|
| Skan „zakończył się”, ale 0 hostów i 0 portów | Zakres jest w innej sieci niż komputer (inny router). W dzienniku skanu i na stronie skanu jest ostrzeżenie. Podłącz się do właściwej sieci lub zmień zakres. |
| W topologii nie widać wcześniejszych urządzeń | Domyślnie pokazywana jest bieżąca sieć. Użyj przełącznika **Sieć → Wszystkie sieci** (lub wybierz starą sieć). |
| Nie można uruchomić skanu | Zakres nie jest zatwierdzony, trwa inny skan tego zakresu, albo poprzedni skan jest wstrzymany (wtedy go wznow lub zakończ). |
| „Brak połączenia z DefectDojo” | Sprawdź adres, token, TLS (samopodpisany certyfikat → tylko dla laba wyłącz weryfikację) i czy używasz roli z uprawnieniem *manage*. |
| Brak dopasowań CVE | Usługa nie ma wersji z banera/protokołu albo lokalna baza nie była aktualizowana (**Podatności → Aktualizuj z Internetu**). |
| Sprawdzający szuka integracji z nmap | WELES **nie uruchamia binarnego nmap**. Skanuje własnym silnikiem; obsługuje natomiast **import wyników** z `nmap -oX` (XML), CSV i JSON. |
| Sprawdzający chce dodać urządzenie ręcznie | WELES nie tworzy nowych urządzeń „z ręki”. Dane ręczne to edycja urządzenia już wykrytego (**Urządzenia → Edytuj**: nazwa, typ, krytyczność, notatki); nowe dane wprowadza się przez zakresy/import wyników. |
