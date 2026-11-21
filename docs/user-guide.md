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
| Powierzchnia ataku | domeny, DNS, SPF/DMARC, subdomeny z CT, certyfikaty, usługi publiczne | ✅ Etap 8 |
| Vulnerabilities | dopasowania CVE (NVD, KEV, EPSS), lokalna baza i jej aktualizacja | ✅ Etap 4 |
| Ocena ryzyka | Security Posture Score, trend, priorytety napraw, ocena każdego urządzenia z uzasadnieniem | ✅ Etap 5 |
| Topologia / Ścieżki ataku / Monitorowanie | mapa sieci, hipotetyczne ścieżki ekspozycji, zmiany między skanami, harmonogram | ✅ Etap 7 |
| Analityk AI | lokalny asystent: wyjaśnia podatności, ryzyko, zmiany, priorytety napraw | ✅ Etap 6 |
| Raporty | raport PDF, eksport JSON/ZIP, import audytu, podsumowanie AI audytu | ✅ Etap 9 |
| Agenci | zdalni agenci w innych segmentach sieci: rejestracja, zakresy, zlecanie skanów, unieważnianie | ✅ Etap 10 |
| Settings | wersja, ścieżki, baza, AI, motyw, pobieranie logów | Etap 1 |

Wszystkie moduły są zaimplementowane.

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

### Skan w tle

Skan działa na serwerze WELES, niezależnie od otwartej strony: można przechodzić między zakładkami albo zamknąć kartę
przeglądarki. Trwający skan jest widoczny w górnym pasku każdej strony (numer, zakres, etap, procent – kliknięcie
otwiera postęp); po zakończeniu przez minutę widać tam link „Skan #N zakończony – zobacz wyniki”. W Wykrywaniu sieci
zakres ze skanem w toku ma przycisk „Skan w toku – pokaż postęp”. Skan przerywa tylko „Zatrzymaj skan” albo zamknięcie
aplikacji (wtedy skan jest oznaczany jako przerwany).

## Inwentarz urządzeń (Assets)

- **Wyszukiwanie** – kilka słów naraz (wszystkie muszą pasować): nazwa, IP, MAC, producent, system, produkt
  (np. `openssh`), numer otwartego portu (np. `3389`). Wielkość liter i polskie znaki nie mają znaczenia (`lodz` = `Łódź`).
- **Filtry** – status, typ, segment, system, „z otwartymi portami”; liczby przy filtrach pokazują, ile urządzeń zostanie.
- **Sortowanie** – klik w nagłówek; **Shift+klik** dodaje kolejny poziom (np. porty ↓, potem nazwa ↑).
- **Kolumny** – przycisk „Kolumny”; wybór jest zapamiętywany.
- **Jedno urządzenie, kilka adresów** – urządzenie podłączone kablem i przez Wi‑Fi ma dwa adresy MAC. Jeśli pod obydwoma
  działa SSH z tym samym kluczem hosta (np. Raspberry Pi), WELES łączy je w jedno urządzenie; w szczegółach widać oba
  interfejsy i powód połączenia. Klucz jest odczytywany bez logowania, tak jak robi to `ssh-keyscan`.
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
  sprawdź ją w panelu urządzenia; albo NVD oznacza „wszystkie wersje” produktu, więc wersja niczego nie rozstrzyga.
  CVE, które NVD wiąże z inną dystrybucją niż wykryta (np. tylko pakiety Red Hata, a baner wskazuje Debiana), nie są
  dopasowywane.
  Każde dopasowanie ma uzasadnienie (najedź na wiersz) i procent pewności.
- **Status podatności**: *Otwarte*; *Rozwiązane* – kolejny skan nie potwierdził dowodu (np. nowsza wersja);
  *Zaakceptowane* – świadoma decyzja w szczegółach CVE (przycisk „Akceptuj ryzyko”), zachowywana przez kolejne skany.
- **Szczegóły CVE** – opis z NVD, CVSS, EPSS, obecność w CISA KEV, podatne zakresy wersji, referencje i lista urządzeń.

## Ocena ryzyka

- **Security Posture Score** (0–100, wyżej = lepiej) dla każdej sieci: 100 − (½ oceny najbardziej zagrożonego
  urządzenia + ½ średniej pięciu najbardziej zagrożonych). Zapisywany po każdym skanie – wykres pokazuje trend.
- **Ocena urządzenia** (0–100, wyżej = gorzej): najpoważniejszy problem + 10% pozostałych, potem krytyczność
  urządzenia (ustawiana w szczegółach urządzenia), rola (router, serwer, NAS), ekspozycja, liczba usług, wiek
  oprogramowania i nowe porty. W szczegółach urządzenia widać każdy składnik z liczbą punktów.
- **Problemy**: podatności (CVSS, CISA KEV, EPSS, pewność dopasowania; CVE jednego programu to jedna pozycja
  „Zaktualizuj…”) i problemy konfiguracji (np. Telnet, Redis bez hasła, ADB przez sieć, logowanie bez szyfrowania,
  certyfikaty). Każdy ma dowód, zalecenie i techniki MITRE ATT&CK.
- **Priorytety napraw** – lista „co naprawić najpierw”: ocena problemu wzmocniona kontekstem urządzenia.
- **Akceptuj ryzyko** (szczegóły urządzenia / CVE) – świadoma decyzja; problem zostaje w historii, ale nie podnosi oceny.
- Poziomy: Critical ≥ 80, High ≥ 60, Medium ≥ 35, Low ≥ 15, Informational.

## Monitorowanie, topologia i ścieżki ataku

- **Monitorowanie** odpowiada na pytanie „co zmieniło się od ostatniego audytu?”: porównuje ostatni skan z poprzednim
  skanem tej samej sieci (można wybrać dowolne dwa) – nowe i znikające urządzenia, nowe i zamknięte porty, zmiany usług,
  wersji i certyfikatów, nowe i rozwiązane podatności, zmiany ryzyka i Security Posture Score. Porty są porównywane tylko,
  jeśli oba skany je sprawdzały. Tabela „Zmiany w czasie” pokazuje to dla każdego skanu.
- **Harmonogram** (Wykrywanie sieci, przy zatwierdzonym zakresie): co godzinę, co 6 godzin, codziennie lub co tydzień.
  Najpierw trzeba raz uruchomić zakres ręcznie – ten skan ustala sieć (router). Skan automatyczny jest pomijany, gdy
  zakres nie jest zatwierdzony albo komputer jest w innej sieci (inny router), nawet przy tym samym zakresie adresów;
  przyczyna jest widoczna przy zakresie.
- **Topologia** – mapa: Internet, router, urządzenia z kolorem ryzyka; przerywany pierścień = punkt ekspozycji.
  Połączenia wynikają z adresów i bram, nie z obserwacji ruchu. Kliknięcie urządzenia pokazuje szczegóły.
- **Ścieżki ataku** – hipotezy, jak można dotrzeć do urządzenia: start (założenie), dostęp (otwarty port), słabość
  (podatność lub problem konfiguracji) i możliwy skutek. Każdy krok ma uzasadnienie i pewność, ścieżka – pewność łączną.
  To nie są potwierdzone ataki; WELES niczego nie próbuje wykorzystać.

## Podział na sieci

Pulpit, Ocena ryzyka, Ścieżki ataku, Podatności, Topologia i Monitorowanie mają przełącznik **Sieć**: bieżąca sieć
(domyślnie), wszystkie sieci, konkretna sieć (router rozpoznany po adresie MAC, VPN) albo zasoby publiczne – każda
domena z modułu Powierzchnia ataku osobno. Wybór jest zapisany w adresie strony (`?net=`), więc linki go zachowują.
Ocena stanu bezpieczeństwa jest liczona osobno dla każdej sieci.

Maszyny dostępne przez VPN (np. laboratoria TryHackMe) dodaje się w Wykrywaniu sieci jako zakres z **pojedynczym
adresem** – WELES nie proponuje zakresu całej sieci VPN, bo są w niej komputery innych osób.

## Powierzchnia ataku (domeny i adresy publiczne)

- Dodaj **własną** domenę lub publiczny adres IP i potwierdź, że należy do Ciebie (albo masz pisemną zgodę właściciela).
- **Analiza pasywna** nie łączy się z Twoimi serwerami: pyta serwery DNS systemu o rekordy A, AAAA, MX, NS, TXT, CAA, SOA
  i DMARC, a – jeśli zaznaczysz – szuka subdomen w publicznych logach Certificate Transparency (crt.sh dostaje tylko
  nazwę domeny). WELES nie zgaduje nazw; możesz dopisać znane subdomeny. Wynik: uwagi z cytowanym rekordem (np. SPF „+all”,
  brak DMARC, CNAME wskazujący na nieistniejącą nazwę, adres wewnętrzny w publicznym DNS), tabela rekordów, hostów
  i certyfikatów z CT.
- **Skanowanie aktywne** jest osobnym krokiem: zaznacz hosty → „Przygotuj zakres skanowania” → zatwierdź zakres
  w Wykrywaniu sieci (ponowne potwierdzenie uprawnień) → uruchom skan (zalecany profil Szybki). Wyniki – otwarte porty
  publiczne, usługi administracyjne dostępne z Internetu, certyfikaty TLS i uwagi – pojawią się na stronie Powierzchni ataku.
  Upewnij się, że dostawca hostingu pozwala na skanowanie.

## Raporty

Audyt to jeden zakończony skan. **Raporty** pokazują wszystkie audyty (z przełącznikiem sieci); przycisk **Raport audytu**
jest też na stronie skanu.

- **Raport PDF** – dane audytu, data, zakres, podsumowanie infrastruktury, lista urządzeń, usługi, podatności (CVE)
  i problemy konfiguracji (np. FTP bez szyfrowania), poziomy ryzyka, rekomendacje w kolejności napraw, zmiany od
  poprzedniego audytu tej sieci oraz podsumowanie AI, jeśli je wygenerowano. Język PDF = język interfejsu.
- **Eksport ZIP** – `audit.json` + `report.pdf` + `manifest.json` z sumami SHA‑256; **Eksport JSON** – sam `audit.json`.
  Pliki trafiają do katalogów `reports/` i `exports/`; lista „Wygenerowane pliki” pozwala je pobrać ponownie.
- **Podsumowanie AI** – na żądanie, przez lokalny model, wyłącznie z danych tego audytu.
- **Import audytu** – wybierz ZIP lub JSON z innego WELES. Plik jest sprawdzany (dozwolone pliki, sumy SHA‑256, format,
  rozmiary). Zaimportowany audyt otwiera się tylko do odczytu i nie miesza się z urządzeniami tego komputera; można
  z niego wygenerować PDF.

Raport opisuje stan z chwili skanu – późniejsze skany nie zmieniają starszego raportu.

## Agenci

WELES działa w pełni bez agentów. Agent przydaje się, gdy chcesz skanować sieć, do której ten komputer nie ma dostępu
(inne biuro, inny segment).

1. **Agenci → Punkt połączeń agentów**: zaznacz „Włącz”, wybierz adres tego komputera (sieć lokalna lub VPN) i port,
   zapisz i uruchom ponownie WELES. Zapora musi przepuszczać ten port.
2. **Nowy agent**: nazwa i zakresy, które agent może skanować (tylko zakresy sieci lokalnej: adresy, CIDR, przedziały).
   WELES pokaże jednorazowy kod i gotowe polecenie `weles-agent enroll …` z odciskiem certyfikatu.
3. Na komputerze agenta: Linux – rozpakuj paczkę, zarejestruj agenta i włącz usługę `weles-agent` (plik
   `weles-agent.service`); Windows – `install-agent.ps1 -Server … -Pin … -Code …` jako administrator.
4. Gdy agent jest „połączony”, wybierz zatwierdzony zakres i **Zleć skan**. Skan pojawia się w **Skanach**, można go
   zatrzymać, a wyniki trafiają do wszystkich stron jak skan lokalny.
5. **Unieważnij** odcina agenta natychmiast.

## Rozszerzenie AGH

- **Pierwsze uruchomienie:** WELES prosi o konto administratora. Kolejnych użytkowników dodaje się w **Użytkownicy** z jedną
  z ról: Administracja; Dodawanie, usuwanie, modyfikacja; Modyfikacja i odczyt; Odczyt.
- **Usługi web:** każda usługa HTTP/HTTPS z tytułem, kodem, nagłówkami, ciasteczkami, przekierowaniami, favicon i
  technologiami (CMS, frameworki, panele, staging, IoT) oraz oceną „ciekawości”. Eksport CSV/JSON.
- **Sygnatury:** własne reguły w JSON (szablon w edytorze), test na zebranych danych, import i eksport.
- **Skany → Import i eksport wyników:** nmap XML, CSV, JSON; cele zakresu z pliku w formularzu zakresu.
- **Integracje → DefectDojo:** adres, klucz API, produkt/engagement/test, wybór granularności, podgląd, wysyłanie lub plik.
- Baza jest szyfrowana automatycznie (SQLCipher) – plik `data/weles.db` bez `keys/database.key` jest nieczytelny.
- **Duże zakresy:** powyżej 1024 adresów skan idzie podgrupami. Na stronie skanu widać numer podgrupy, gotowe adresy i
  szacowany koniec; w zdarzeniach – tempo każdej podgrupy. **Wstrzymaj** kończy bieżącą podgrupę i zatrzymuje skan;
  **Wznów skan** kontynuuje od następnej (nic nie jest skanowane drugi raz); **Zakończ bez wznawiania** zostawia zebrane wyniki.
- **Nmap (opcjonalnie):** jeśli nmap jest zainstalowany (Ustawienia pokazują wersję), w **Wykrywanie sieci** obok profilu
  portów wybierz **nmap**. Nmap szuka otwartych portów i wersji usług, a WELES nadal rozpoznaje usługi web, sygnatury i
  podatności. Bez nmapa wszystko działa na silniku WELES. Instalacja: Linux `sudo apt install nmap`, Windows – instalator z nmap.org.
- **Okno czasowe harmonogramu:** w **Wykrywanie sieci** przy harmonogramie zakresu ustaw np. 22:00–06:00. Skany startują
  tylko w oknie; skan, który nie zdąży, zostaje wstrzymany i wznawia się sam w kolejnym oknie.
- **Niestabilne urządzenia:** urządzenie, które nie odpowiedziało w ostatnim skanie (lub dwóch), ma status **Niestabilne**;
  **Nieobecne** dopiero po 3 kolejnych skanach bez odpowiedzi. Na stronie urządzenia: w ilu skanach odpowiadało, ile razy z
  rzędu milczy i czy zależy to od pory dnia (np. „odpowiada w godzinach 06:00–18:00, nie odpowiada 00:00–06:00”).
- **Topologia z dowodami:** linia ciągła – połączenie zaobserwowane (MAC w tablicy ARP, TTL odpowiedzi bez zmian),
  kropkowana – przez routery (TTL obniżony albo traceroute, z liczbą hopów), przerywana – tylko wywnioskowane z adresu i
  bramy. Najedź na linię lub kliknij urządzenie, aby zobaczyć dowód; karta sieci pokazuje liczniki i routery z traceroute.
- **Dostęp z sieci lokalnej:** **Ustawienia → Dostęp z sieci lokalnej** (administrator): wybierz adres tego komputera i port,
  zapisz, uruchom ponownie WELES. Panel będzie pod `https://adres:port` dla komputerów z tej samej podsieci, po zalogowaniu.
  Przeglądarka ostrzeże o certyfikacie samopodpisanym – porównaj odcisk SHA-256 z Ustawień.

## Analityk AI

- Lokalny model językowy (Qwen3‑4B, dołączony do WELES) odpowiada na pytania o Twoją sieć **wyłącznie na podstawie
  danych WELES**; działa bez Internetu i nic nie wysyła poza komputer. Uruchamia się sam przy starcie WELES.
- Przykłady: „Jakie są trzy największe zagrożenia w mojej sieci?”, „Które podatności powinienem naprawić najpierw?”,
  „Czy pojawiły się nowe urządzenia od ostatniego skanowania?”, „Wyjaśnij CVE‑2023‑38408”, „Przygotuj podsumowanie
  ostatniego audytu”. Przyciski „Wyjaśnij z Analitykiem AI” (strona CVE) i „Zapytaj Analityka AI” (ocena ryzyka
  urządzenia) zadają pytanie od razu.
- Pod odpowiedzią widać, jakie dane dostał model, ile trwała odpowiedź i z jaką szybkością. Odpowiedź można zatrzymać.
- Analityk nie uruchamia skanów ani poleceń – tylko wyjaśnia i doradza. Gdy danych brakuje, mówi to i podpowiada, co
  zrobić w WELES.
- Na komputerze bez karty graficznej pierwsza odpowiedź trwa zwykle od kilkunastu sekund do ok. minuty (czytanie danych
  przez model), potem tekst pojawia się na bieżąco.

## Telefony i tablety

WELES sprawdza, co telefon **wystawia w sieci**: otwarte porty, ADB przez sieć (z autoryzacją lub bez), debugowanie
bezprzewodowe (wykrywane przez mDNS), serwery udostępniania plików. Telefony zwykle mają losowy adres MAC, więc
producent nie jest znany. Wersji Androida/iOS i poprawek bezpieczeństwa nie da się odczytać z sieci.
Aby przetestować wykrywanie, włącz na telefonie *Opcje programisty → Debugowanie bezprzewodowe* i uruchom skan.

## Język

Przełącznik **PL / EN** w górnym pasku (oraz w Ustawieniach → Wygląd) zmienia język całego interfejsu. Wybór jest
zapisywany w lokalnej bazie; strona przeładowuje się w nowym języku. Komunikaty zapisane wcześniej przez WELES
(dziennik skanu, uzasadnienia klasyfikacji i dopasowań, nazwy zakresów utworzonych automatycznie) też są wyświetlane
w wybranym języku. Opisy CVE pochodzą z NVD i są zawsze po angielsku; nazwy nadane przez Ciebie się nie zmieniają.

## Uruchamianie po zalogowaniu

*Ustawienia → Uruchamianie*: WELES startuje po zalogowaniu w tle (bez otwierania przeglądarki). Skrót WELES otwiera
panel już działającej aplikacji. Ta sama opcja jest w instalatorze Windows.

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
