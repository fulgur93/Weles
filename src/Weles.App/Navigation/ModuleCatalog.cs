namespace Weles.App.Navigation;

public sealed record WelesModule(
    string Title,
    string Route,
    string Icon,
    string Group,
    int Stage,
    bool IsAvailable,
    string Summary,
    IReadOnlyList<string> PlannedCapabilities);

/// <summary>
/// Single source of truth for navigation. Texts are Polish dictionary keys – the UI shows them through <see cref="Localization.L"/>. A module that is not
/// implemented yet would be shown as "planned" with its delivery stage – never as an empty, seemingly working screen.
/// </summary>
public static class ModuleCatalog
{
    public static IReadOnlyList<WelesModule> All { get; } =
    [
        new("Pulpit", "", "dashboard", "Przegląd", 1, true,
            "Stan bezpieczeństwa infrastruktury na podstawie rzeczywistych danych z bazy.", []),

        new("Urządzenia", "assets", "assets", "Rozpoznanie", 3, true,
            "Inwentarz urządzeń z historią obserwacji, usługami, podatnościami i oceną ryzyka.",
            ["Wyszukiwanie, sortowanie wielokolumnowe, filtry i paginacja", "Wybór kolumn", "Szczegóły urządzenia: porty, usługi, wersje, historia zmian", "Krytyczność zasobu ustawiana przez użytkownika"]),
        new("Wykrywanie sieci", "discovery", "discovery", "Rozpoznanie", 2, true,
            "Wykrywanie interfejsów i segmentów sieci oraz urządzeń w zatwierdzonym zakresie.",
            ["Automatyczne wykrycie lokalnych interfejsów i zakresów CIDR", "Zakresy skanowania z allowlistą, wykluczeniami i zatwierdzeniem", "ICMP, TCP connect, pasywny odczyt tablicy ARP, DNS", "Rozpoznanie producenta po OUI adresu MAC"]),
        new("Skany", "scans", "scans", "Rozpoznanie", 2, true,
            "Uruchamianie, podgląd na żywo, zatrzymywanie i historia skanowań.",
            ["Skanowanie portów z limitem równoległości i szybkości", "Rozpoznawanie usług i wersji z poziomem pewności", "Analiza TLS, certyfikatów i nagłówków HTTP", "Możliwość zatrzymania skanu w dowolnym momencie"]),
        new("Usługi web", "web", "surface", "Rozpoznanie", 12, true,
            "Usługi HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka, przekierowania, favicon i technologie rozpoznane sygnaturami.",
            ["CMS, frameworki, serwery, urządzenia IoT", "Panele administracyjne i środowiska testowe", "Ocena ciekawości z uzasadnieniem", "Eksport CSV/JSON"]),
        new("Powierzchnia ataku", "attack-surface", "surface", "Rozpoznanie", 8, true,
            "Zewnętrzna powierzchnia ataku: domeny, DNS, certyfikaty i publiczne usługi – tylko zasoby, do których masz uprawnienia.",
            ["Rekordy A, AAAA, MX, NS, TXT", "Subdomeny z autoryzowanych źródeł (Certificate Transparency)", "Rozdzielenie analizy pasywnej od aktywnego skanowania"]),

        new("Podatności", "vulnerabilities", "vulnerabilities", "Analiza", 4, true,
            "Dopasowanie wykrytych wersji do znanych podatności z lokalnej bazy NVD, CISA KEV i EPSS.",
            ["Lokalna baza działająca offline z datą aktualizacji", "Dopasowanie po producencie, produkcie i zakresach wersji", "Statusy: potwierdzone, prawdopodobne, wymaga weryfikacji, brak danych", "Uwzględnienie poprawek dystrybucyjnych (backporty)"]),
        new("Ocena ryzyka", "risk", "risk", "Analiza", 5, true,
            "Kontekstowa ocena ryzyka z pełnym uzasadnieniem każdej oceny.",
            ["CVSS, EPSS, KEV, ekspozycja, krytyczność zasobu i pewność wykrycia", "Klasyfikacja Critical / High / Medium / Low / Informational", "Security Posture Score i trend w czasie", "Priorytety napraw"]),
        new("Sygnatury", "signatures", "check", "Analiza", 12, true,
            "Bezpieczne sygnatury detekcyjne: wbudowane i własne (nagłówek, ciasteczko, HTML, favicon, ścieżka bez logowania).",
            ["Edytor JSON z testem na zebranych danych", "Import i eksport", "Działają też na wcześniejszych skanach"]),
        new("Topologia sieci", "topology", "topology", "Analiza", 7, true,
            "Interaktywna mapa segmentów, urządzeń i usług z wyróżnieniem punktów ekspozycji.",
            ["Wizualizacja SVG renderowana w Blazorze", "Kliknięcie urządzenia otwiera szczegóły", "Wyróżnienie urządzeń wysokiego ryzyka"]),
        new("Ścieżki ataku", "attack-paths", "paths", "Analiza", 7, true,
            "Potencjalne ścieżki ekspozycji – każdy krok z uzasadnieniem i poziomem pewności. Hipotezy, nie potwierdzone ataki.",
            ["Ścieżki od Internetu/segmentu do krytycznych zasobów", "Uzasadnienie i pewność każdego kroku", "Brak jakichkolwiek prób wykorzystania podatności"]),
        new("Monitorowanie", "monitoring", "monitoring", "Analiza", 7, true,
            "Co zmieniło się w sieci od ostatniego audytu.",
            ["Nowe i znikające urządzenia, porty, usługi i podatności", "Zmiany wersji i certyfikatów", "Harmonogram skanów – wyłącznie dla zatwierdzonych zakresów"]),

        new("Analityk AI", "ai", "ai", "Inteligencja", 6, true,
            "Lokalny asystent bezpieczeństwa (Ollama + model Q4 dołączone do instalatora). Analizuje wyłącznie dane z bazy WELES.",
            ["Wyjaśnianie podatności prostym językiem", "Priorytety napraw i rekomendacje", "Podsumowania audytów i zmian między skanami", "Działa offline – dane nie opuszczają komputera"]),
        new("Raporty", "reports", "reports", "Inteligencja", 9, true,
            "Raporty PDF oraz eksport/import audytu (JSON/ZIP) do przeniesienia na inny komputer.",
            ["Raport PDF z podsumowaniem, urządzeniami, podatnościami i rekomendacjami", "Zmiany od poprzedniego audytu", "Eksport i import pełnego audytu"]),

        new("Agenci", "agents", "agents", "System", 10, true,
            "Opcjonalne agenty (Windows/Linux) skanujące inne segmenty sieci i raportujące przez wychodzące HTTPS.",
            ["Rejestracja i unieważnianie dostępu", "Uwierzytelniona komunikacja wychodząca", "Wyłącznie zatwierdzone zakresy"]),
        new("Integracje", "integrations", "layers", "System", 12, true,
            "DefectDojo: wysyłanie znalezisk (CVE, CWE, CVSS, EPSS, konfiguracja, technologie) z wybraną granularnością.",
            ["Reimport do stałego testu – śledzenie zmian", "Plik Generic Findings Import", "Klucz API szyfrowany"]),
        new("Użytkownicy", "users", "lock", "System", 12, true,
            "Konta i role (RBAC): Administracja, Dodawanie/usuwanie/modyfikacja, Modyfikacja i odczyt, Odczyt.", []),
        new("Ustawienia", "settings", "settings", "System", 1, true,
            "Ustawienia aplikacji, ścieżki danych, baza, silnik AI i logi.", []),
    ];

    public static IEnumerable<IGrouping<string, WelesModule>> Groups => All.GroupBy(m => m.Group);

    public static WelesModule? FindByRoute(string route) =>
        All.FirstOrDefault(m => string.Equals(m.Route, route.Trim('/'), StringComparison.OrdinalIgnoreCase));
}
