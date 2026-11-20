using System.Globalization;
using System.Text.RegularExpressions;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Weles.App.Localization;
using Weles.App.Services;
using Weles.Core.Enums;
using Weles.Core.Reports;

namespace Weles.App.Reports;

/// <summary>
/// The PDF audit report (QuestPDF, rendered in-process – nothing leaves the computer). It renders an
/// <see cref="AuditDocument"/>, so a local audit and an imported one produce the same report. The language follows
/// the UI (<see cref="L"/>); texts WELES stored in Polish are translated with <see cref="L.Message"/>.
/// </summary>
public static partial class AuditPdfRenderer
{
    private const string Ink = "#111827";
    private const string Muted = "#6b7280";
    private const string Line = "#e5e7eb";
    private const string Accent = "#1e3a8a";
    private const int MaxDeviceDetails = 60;

    static AuditPdfRenderer()
    {
        // Community license: free for individuals and organisations under 1 M USD annual revenue (docs/architecture.md, R12).
        QuestPDF.Settings.License = LicenseType.Community;
        // Fonts bundled with QuestPDF only – the report looks the same on every system and never depends on installed fonts.
        QuestPDF.Settings.UseSystemFonts = false;
    }

    /// <param name="imported">The audit came from a file exported by another WELES installation.</param>
    public static byte[] Render(AuditDocument d, bool imported = false)
    {
        var culture = CultureInfo.CurrentCulture;
        var created = DateTime.UtcNow;
        return Document.Create(container => container.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(32);
            page.DefaultTextStyle(x => x.FontSize(8.5f).FontColor(Ink).LineHeight(1.25f));

            page.Header().PaddingBottom(8).BorderBottom(0.5f).BorderColor(Line).Row(row =>
            {
                row.RelativeItem().Text(t =>
                {
                    t.Span("WELES").Bold().FontColor(Accent);
                    t.Span("  " + L.T("Raport audytu bezpieczeństwa")).FontColor(Muted);
                });
                row.AutoItem().AlignRight().Text(L.F("Skan #{0}", d.Audit.ScanId) + " · " + Labels.Local(d.Audit.StartedAt)).FontColor(Muted);
            });

            page.Footer().PaddingTop(6).BorderTop(0.5f).BorderColor(Line).Row(row =>
            {
                row.RelativeItem().Text(L.F("Wygenerowano lokalnie: {0} · {1} · dokument poufny", d.GeneratedBy, Labels.Local(created))).FontSize(7).FontColor(Muted);
                row.AutoItem().AlignRight().Text(t =>
                {
                    t.DefaultTextStyle(x => x.FontSize(7).FontColor(Muted));
                    t.CurrentPageNumber();
                    t.Span(" / ");
                    t.TotalPages();
                });
            });

            page.Content().PaddingTop(10).Column(col =>
            {
                col.Spacing(10);
                TitleSection(col, d, imported);
                SummarySection(col, d, culture);
                if (d.AiSummary is { } ai) AiSection(col, ai);
                RecommendationsSection(col, d, culture);
                ChangesSection(col, d);
                DevicesSection(col, d, culture);
                DeviceDetails(col, d, culture);
                NotesSection(col);
            });
        })).GeneratePdf();
    }

    private static void TitleSection(ColumnDescriptor col, AuditDocument d, bool imported)
    {
        var a = d.Audit;
        col.Item().Text(L.T("Raport audytu bezpieczeństwa")).FontSize(20).Bold().FontColor(Accent);
        col.Item().Text(Title(a)).FontSize(11).SemiBold();
        if (a.IsDemo) Callout(col, L.T("Dane demonstracyjne – nie pochodzą z prawdziwego skanowania."), "#fef3c7");
        if (imported) Callout(col, L.T("Audyt zaimportowany z pliku eksportu innej instalacji WELES – dane opisują tamtą sieć w chwili audytu."), "#e0e7ff");

        col.Item().Table(t =>
        {
            t.ColumnsDefinition(c => { c.ConstantColumn(150); c.RelativeColumn(); });
            void Row(string label, string value)
            {
                t.Cell().PaddingVertical(2).Text(label).FontColor(Muted);
                t.Cell().PaddingVertical(2).Text(value);
            }

            Row(L.T("Audyt"), L.F("Skan #{0}", a.ScanId) + (a.Trigger == ScanTrigger.Scheduled ? " · " + L.T("z harmonogramu") : ""));
            Row(L.T("Data"), $"{Labels.Local(a.StartedAt)} – {Labels.Local(a.CompletedAt)} ({Labels.Duration(a.StartedAt, a.CompletedAt)})");
            Row(L.T("Zakres skanowania"), a.Scope.Count == 0 ? "—" : string.Join(", ", a.Scope.Select(L.Message)));
            Row(L.T("Sieć"), L.Message(a.Network) + (a.IsExternal ? " · " + L.T("hosty publiczne skanowane przez Internet") : ""));
            Row(L.T("Porty"), a.PortSpecification);
            Row(L.T("Wynik skanu"), L.F("{0} aktywnych urządzeń z {1} adresów, {2} otwartych portów", a.HostsAlive, a.HostsTargeted, a.OpenPorts));
        });
    }

    private static void SummarySection(ColumnDescriptor col, AuditDocument d, CultureInfo culture)
    {
        Heading(col, L.T("Podsumowanie infrastruktury"));
        col.Item().Row(row =>
        {
            row.Spacing(8);
            Tile(row, L.T("Security Posture Score"), d.Posture is { } p ? p.Score.ToString("0", culture) + "/100" : "—",
                d.Posture?.Previous is { } prev ? L.F("poprzednio {0}", prev.ToString("0", culture)) : L.T("100 = najlepiej"));
            Tile(row, L.T("Urządzenia"), d.Devices.Count.ToString(culture), L.F("{0} usług", d.ServiceCount));
            Tile(row, L.T("Podatności (CVE)"), d.VulnerabilityCount.ToString(culture), L.F("{0} w CISA KEV", d.KnownExploitedCount));
            Tile(row, L.T("Problemy konfiguracji"), d.Devices.Sum(x => x.Findings.Count(f => f.Status == FindingStatus.Open)).ToString(culture),
                L.T("np. FTP bez szyfrowania"));
        });

        var byLevel = d.DevicesByLevel;
        col.Item().Text(t =>
        {
            t.Span(L.T("Poziomy ryzyka urządzeń") + ": ").FontColor(Muted);
            foreach (var level in Enum.GetValues<RiskLevel>().Reverse())
            {
                t.Span($"{Labels.Of(level)} {byLevel.GetValueOrDefault(level)}").FontColor(LevelColor(level)).SemiBold();
                if (level != RiskLevel.Informational) t.Span(" · ").FontColor(Muted);
            }
        });

        if (d.Posture is { Factors.Count: > 0 } posture)
        {
            col.Item().Column(c =>
            {
                c.Item().Text(L.T("Z czego wynika wynik")).SemiBold();
                foreach (var f in posture.Factors.Take(8))
                {
                    c.Item().Text($"• {L.Message(f.Text)} ({f.Points.ToString("+0.#;-0.#;0", culture)})").FontColor(Muted);
                }
            });
        }
    }

    private static void AiSection(ColumnDescriptor col, AuditAiSummaryInfo ai)
    {
        Heading(col, L.T("Podsumowanie AI"));
        col.Item().Text(L.F("Wygenerowane przez lokalny model {0} ({1}) wyłącznie z danych tego audytu. To interpretacja – fakty znajdziesz w kolejnych sekcjach.",
            ai.Model ?? "AI", Labels.Local(ai.CreatedAt))).FontSize(7.5f).Italic().FontColor(Muted);
        col.Item().Background("#f8fafc").Border(0.5f).BorderColor(Line).Padding(8).Column(c =>
        {
            c.Spacing(2);
            foreach (var raw in ai.Text.Split('\n'))
            {
                var line = raw.TrimEnd();
                if (line.Length == 0) continue;
                var heading = HeadingMarker().Match(line);
                if (heading.Success)
                {
                    c.Item().PaddingTop(4).Text(StripMarkdown(heading.Groups[1].Value)).SemiBold().FontColor(Accent);
                }
                else if (BulletMarker().Match(line) is { Success: true } bullet)
                {
                    c.Item().PaddingLeft(8).Text("• " + StripMarkdown(bullet.Groups[1].Value));
                }
                else
                {
                    c.Item().Text(StripMarkdown(line));
                }
            }
        });
    }

    private static void RecommendationsSection(ColumnDescriptor col, AuditDocument d, CultureInfo culture)
    {
        Heading(col, L.T("Rekomendacje – kolejność napraw"));
        if (d.Recommendations.Count == 0)
        {
            col.Item().Text(L.T("Brak problemów do naprawy w tym audycie.")).FontColor(Muted);
            return;
        }

        col.Item().Table(t =>
        {
            t.ColumnsDefinition(c => { c.ConstantColumn(18); c.ConstantColumn(62); c.RelativeColumn(2); c.RelativeColumn(3); c.RelativeColumn(4); });
            HeaderRow(t, "#", L.T("Priorytet"), L.T("Urządzenie"), L.T("Problem"), L.T("Co zrobić"));
            var i = 0;
            foreach (var r in d.Recommendations)
            {
                i++;
                Cell(t).Text(i.ToString(culture)).FontColor(Muted);
                Cell(t).Text(t2 =>
                {
                    t2.Line(r.Priority.ToString("0", culture)).Bold().FontColor(LevelColor(r.Level));
                    t2.Span(Labels.Of(r.Level)).FontSize(7).FontColor(LevelColor(r.Level));
                });
                Cell(t).Text(t2 =>
                {
                    t2.Line(L.Message(r.Device));
                    if (r.Ip is not null && !r.Device.Contains(r.Ip, StringComparison.Ordinal)) t2.Span(r.Ip).FontSize(7).FontColor(Muted);
                });
                Cell(t).Text(t2 =>
                {
                    t2.Line(L.Message(r.Title) + (r.Port is { } port ? $" ({L.F("port {0}", port)})" : ""));
                    if (r.KnownExploited > 0) t2.Span(L.T("CVE w katalogu CISA KEV – znane wykorzystanie w atakach")).FontSize(7).FontColor(LevelColor(RiskLevel.Critical));
                });
                Cell(t).Text(L.Message(r.Recommendation));
            }
        });
    }

    private static void ChangesSection(ColumnDescriptor col, AuditDocument d)
    {
        Heading(col, L.T("Zmiany od poprzedniego audytu"));
        if (d.Changes is not { } ch)
        {
            col.Item().Text(L.T("To pierwszy audyt tej sieci – nie ma z czym porównać.")).FontColor(Muted);
            return;
        }

        col.Item().Text(L.F("Porównanie ze skanem #{0} z {1}.", ch.PreviousScanId, Labels.Local(ch.PreviousAt))
                        + (ch.PostureBefore is { } b && ch.PostureAfter is { } a ? " " + L.F("Security Posture Score: {0} → {1}.", b.ToString("0"), a.ToString("0")) : ""))
            .FontColor(Muted);
        if (ch.Items.Count == 0)
        {
            col.Item().Text(L.T("Brak zmian – sieć wygląda tak samo jak podczas poprzedniego audytu."));
            return;
        }

        col.Item().Table(t =>
        {
            t.ColumnsDefinition(c => { c.RelativeColumn(2); c.RelativeColumn(2); c.RelativeColumn(4); });
            HeaderRow(t, L.T("Zmiana"), L.T("Urządzenie"), L.T("Szczegóły"));
            foreach (var item in ch.Items.OrderBy(i => i.Kind).Take(200))
            {
                Cell(t).Text(ChangeLabel(item.Kind)).FontColor(ChangeColor(item.Kind));
                Cell(t).Text(L.Message(item.Device));
                Cell(t).Text(L.Message(item.Description));
            }
        });
        if (ch.Items.Count > 200) col.Item().Text(L.F("… oraz {0} kolejnych zmian (pełna lista w eksporcie JSON).", ch.Items.Count - 200)).FontColor(Muted);
    }

    private static void DevicesSection(ColumnDescriptor col, AuditDocument d, CultureInfo culture)
    {
        col.Item().PageBreak();
        Heading(col, L.T("Lista urządzeń"));
        if (d.Devices.Count == 0)
        {
            col.Item().Text(L.T("Skan nie wykrył żadnego urządzenia.")).FontColor(Muted);
            return;
        }

        col.Item().Table(t =>
        {
            t.ColumnsDefinition(c => { c.RelativeColumn(3); c.RelativeColumn(2); c.RelativeColumn(2); c.RelativeColumn(2); c.ConstantColumn(40); c.ConstantColumn(40); c.ConstantColumn(60); });
            HeaderRow(t, L.T("Urządzenie"), L.T("Adres IP"), L.T("Typ"), L.T("Krytyczność"), L.T("Usługi"), "CVE", L.T("Ryzyko"));
            foreach (var dev in d.Devices)
            {
                Cell(t).Text(t2 =>
                {
                    t2.Line(L.Message(dev.Name) + (dev.IsGateway ? " · " + L.T("brama") : ""));
                    if (dev.Vendor is not null) t2.Span(dev.Vendor).FontSize(7).FontColor(Muted);
                });
                Cell(t).Text(dev.Ip ?? "—");
                Cell(t).Text(Labels.Of(dev.Type));
                Cell(t).Text(Labels.Of(dev.Criticality));
                Cell(t).Text(dev.Services.Count.ToString(culture));
                Cell(t).Text(dev.Vulnerabilities.Count(v => v.Status == FindingStatus.Open).ToString(culture));
                Cell(t).Text(dev.RiskLevel is { } level ? $"{(dev.RiskScore ?? 0).ToString("0", culture)} {Labels.Of(level)}" : "—")
                    .FontColor(dev.RiskLevel is { } l ? LevelColor(l) : Muted);
            }
        });
    }

    private static void DeviceDetails(ColumnDescriptor col, AuditDocument d, CultureInfo culture)
    {
        var detailed = d.Devices.Where(x => x.Services.Count > 0 || x.Vulnerabilities.Count > 0 || x.Findings.Count > 0).Take(MaxDeviceDetails).ToList();
        if (detailed.Count == 0) return;
        Heading(col, L.T("Wykryte usługi, podatności i problemy – szczegóły urządzeń"));
        foreach (var dev in detailed)
        {
            col.Item().Column(c =>
            {
                c.Spacing(4);
                c.Item().Background("#f1f5f9").Padding(5).Row(row =>
                {
                    row.RelativeItem().Text(t =>
                    {
                        t.Span(L.Message(dev.Name)).Bold();
                        if (dev.Ip is not null && !dev.Name.Contains(dev.Ip, StringComparison.Ordinal)) t.Span("  " + dev.Ip).FontColor(Muted);
                        t.Span("  " + Labels.Of(dev.Type) + (dev.Os is null ? "" : " · " + dev.Os) + (dev.Model is null ? "" : " · " + dev.Model)).FontColor(Muted);
                    });
                    if (dev.RiskLevel is { } level)
                    {
                        row.AutoItem().Text(L.F("Ryzyko {0} – {1}", (dev.RiskScore ?? 0).ToString("0", culture), Labels.Of(level))).Bold().FontColor(LevelColor(level));
                    }
                });

                if (dev.Services.Count > 0)
                {
                    c.Item().Table(t =>
                    {
                        t.ColumnsDefinition(cd => { cd.ConstantColumn(50); cd.RelativeColumn(2); cd.RelativeColumn(3); cd.RelativeColumn(4); });
                        HeaderRow(t, L.T("Port"), L.T("Usługa"), L.T("Produkt i wersja"), "TLS");
                        foreach (var s in dev.Services)
                        {
                            Cell(t).Text($"{s.Port}/{s.Protocol.ToString().ToLowerInvariant()}");
                            Cell(t).Text(s.Name ?? "—");
                            Cell(t).Text(string.Join(" ", new[] { s.Product, s.Version }.Where(x => !string.IsNullOrEmpty(x))) is { Length: > 0 } pv ? pv : "—");
                            Cell(t).Text(Tls(s));
                        }
                    });
                }

                if (dev.Vulnerabilities.Count > 0)
                {
                    c.Item().Table(t =>
                    {
                        t.ColumnsDefinition(cd => { cd.ConstantColumn(78); cd.ConstantColumn(32); cd.ConstantColumn(36); cd.RelativeColumn(2); cd.RelativeColumn(4); });
                        HeaderRow(t, "CVE", "CVSS", "EPSS", L.T("Pewność dopasowania"), L.T("Opis"));
                        foreach (var v in dev.Vulnerabilities.Take(40))
                        {
                            Cell(t).Text(t2 =>
                            {
                                t2.Line(v.CveId).SemiBold();
                                if (v.IsKnownExploited) t2.Span("CISA KEV").FontSize(7).Bold().FontColor(LevelColor(RiskLevel.Critical));
                            });
                            Cell(t).Text(v.CvssScore?.ToString("0.0", culture) ?? "—");
                            Cell(t).Text(Labels.Epss(v.EpssScore));
                            Cell(t).Text(t2 =>
                            {
                                t2.Line(Labels.Of(v.MatchStatus));
                                t2.Span(string.Join(" ", new[] { v.Product, v.Version }.Where(x => !string.IsNullOrEmpty(x)))
                                        + (v.Status == FindingStatus.Accepted ? " · " + Labels.Of(v.Status) : "")).FontSize(7).FontColor(Muted);
                            });
                            Cell(t).Text(v.Title ?? "—").FontSize(7.5f);
                        }
                    });
                    if (dev.Vulnerabilities.Count > 40) c.Item().Text(L.F("… oraz {0} kolejnych CVE (pełna lista w eksporcie JSON).", dev.Vulnerabilities.Count - 40)).FontColor(Muted);
                }

                if (dev.Findings.Count > 0)
                {
                    c.Item().Table(t =>
                    {
                        t.ColumnsDefinition(cd => { cd.RelativeColumn(3); cd.ConstantColumn(56); cd.RelativeColumn(3); cd.RelativeColumn(4); });
                        HeaderRow(t, L.T("Problem konfiguracji"), L.T("Poziom"), L.T("Dowód"), L.T("Co zrobić"));
                        foreach (var f in dev.Findings)
                        {
                            Cell(t).Text(L.Message(f.Title) + (f.Status == FindingStatus.Accepted ? " · " + Labels.Of(f.Status) : ""));
                            Cell(t).Text(Labels.Of(f.Level)).FontColor(LevelColor(f.Level));
                            Cell(t).Text(L.Message(f.Evidence) is { Length: > 0 } e ? e : "—").FontSize(7.5f);
                            Cell(t).Text(L.Message(f.Recommendation) is { Length: > 0 } r ? r : "—").FontSize(7.5f);
                        }
                    });
                }
            });
        }

        var skipped = d.Devices.Count(x => x.Services.Count > 0 || x.Vulnerabilities.Count > 0 || x.Findings.Count > 0) - detailed.Count;
        if (skipped > 0) col.Item().Text(L.F("Szczegóły {0} kolejnych urządzeń o niższym ryzyku są w eksporcie JSON/ZIP.", skipped)).FontColor(Muted);
    }

    private static void NotesSection(ColumnDescriptor col)
    {
        Heading(col, L.T("Metodyka i ograniczenia"));
        foreach (var note in (string[])[
                     L.T("WELES skanował wyłącznie zakres zatwierdzony przez użytkownika. Nie wykonywał exploitów, prób logowania ani testów niszczących."),
                     L.T("Podatności (CVE) są dopasowane do wersji odczytanych z usług. „Wymaga weryfikacji” oznacza, że wersja może zawierać poprawkę dystrybucji – potwierdź ją ręcznie."),
                     L.T("Problemy konfiguracji (np. FTP bez szyfrowania) nie są numerami CVE – wynikają z reguł WELES i dowodu ze skanu."),
                     L.T("Ocena ryzyka uwzględnia CVSS, EPSS, katalog CISA KEV, rolę i krytyczność urządzenia oraz pewność wykrycia. To ocena priorytetu, nie dowód udanego ataku."),
                     L.T("Raport opisuje stan sieci w chwili audytu. Kolejne skany mogą wykazać inne wyniki.")])
        {
            col.Item().Text("• " + note).FontColor(Muted);
        }
    }

    private static void Heading(ColumnDescriptor col, string text) =>
        col.Item().PaddingTop(6).BorderBottom(1).BorderColor(Accent).PaddingBottom(2).Text(text).FontSize(12).Bold().FontColor(Accent);

    private static void Callout(ColumnDescriptor col, string text, string background) =>
        col.Item().Background(background).Padding(6).Text(text).SemiBold();

    private static void Tile(RowDescriptor row, string label, string value, string note) =>
        row.RelativeItem().Border(0.5f).BorderColor(Line).Padding(6).Column(c =>
        {
            c.Item().Text(label).FontSize(7.5f).FontColor(Muted);
            c.Item().Text(value).FontSize(16).Bold();
            c.Item().Text(note).FontSize(7).FontColor(Muted);
        });

    private static void HeaderRow(TableDescriptor table, params string[] titles) => table.Header(h =>
    {
        foreach (var title in titles) h.Cell().Background("#f1f5f9").Padding(3).Text(title).FontSize(7.5f).SemiBold();
    });

    private static IContainer Cell(TableDescriptor table) => table.Cell().BorderBottom(0.5f).BorderColor(Line).Padding(3);

    private static string Tls(AuditService s)
    {
        if (s.Certificate is not { } c) return s.IsTls ? "TLS" : "—";
        var parts = new List<string> { Tls(c.TlsProtocol), L.F("ważny do {0}", c.NotAfter.ToLocalTime().ToString("d", CultureInfo.CurrentCulture)) };
        if (c.IsSelfSigned) parts.Add(L.T("samopodpisany"));
        if (c.HostnameMatches == false) parts.Add(L.T("nazwa nie pasuje"));
        return string.Join(" · ", parts);
    }

    /// <summary>"Zewnętrzny: firma.pl" or "Dom – 192.168.0.0/24 · TP-LINK" – the scope name only once.</summary>
    public static string Title(AuditInfo a) =>
        a.Network.Contains(a.ScopeName, StringComparison.Ordinal) ? L.Message(a.Network) : L.Message(a.ScopeName) + " – " + L.Message(a.Network);

    /// <summary>"Tls12" (as .NET names it) → "TLS 1.2".</summary>
    public static string Tls(string? protocol) => protocol switch
    {
        null or "" => "TLS",
        "Tls13" => "TLS 1.3",
        "Tls12" => "TLS 1.2",
        "Tls11" => "TLS 1.1",
        "Tls" => "TLS 1.0",
        "Ssl3" => "SSL 3.0",
        "Ssl2" => "SSL 2.0",
        _ => protocol
    };

    private static string LevelColor(RiskLevel level) => level switch
    {
        RiskLevel.Critical => "#b91c1c",
        RiskLevel.High => "#c2410c",
        RiskLevel.Medium => "#a16207",
        RiskLevel.Low => "#1d4ed8",
        _ => Muted
    };

    public static string ChangeLabel(AuditChangeKind kind) => kind switch
    {
        AuditChangeKind.NewDevice => L.T("Nowe urządzenie"),
        AuditChangeKind.ReturnedDevice => L.T("Powrót urządzenia"),
        AuditChangeKind.MissingDevice => L.T("Brak urządzenia"),
        AuditChangeKind.PortOpened => L.T("Otwarty port"),
        AuditChangeKind.PortClosed => L.T("Zamknięty port"),
        AuditChangeKind.ServiceChanged => L.T("Zmiana usługi"),
        AuditChangeKind.VersionChanged => L.T("Zmiana wersji"),
        AuditChangeKind.CertificateChanged => L.T("Zmiana certyfikatu"),
        AuditChangeKind.NewVulnerability => L.T("Nowa podatność"),
        AuditChangeKind.ResolvedVulnerability => L.T("Usunięta podatność"),
        AuditChangeKind.RiskChanged => L.T("Zmiana ryzyka"),
        _ => L.T("Inna zmiana")
    };

    private static string ChangeColor(AuditChangeKind kind) => kind switch
    {
        AuditChangeKind.NewDevice or AuditChangeKind.PortOpened or AuditChangeKind.NewVulnerability => "#c2410c",
        AuditChangeKind.ResolvedVulnerability or AuditChangeKind.PortClosed => "#15803d",
        _ => Ink
    };

    /// <summary>The PDF shows the AI text plainly: emphasis markers and inline code marks are dropped.</summary>
    private static string StripMarkdown(string text) => text.Replace("**", "").Replace("__", "").Replace("`", "").Trim();

    [GeneratedRegex(@"^\s*#{1,6}\s+(.*)$")]
    private static partial Regex HeadingMarker();

    [GeneratedRegex(@"^\s*(?:[-*•]|\d+[.)])\s+(.*)$")]
    private static partial Regex BulletMarker();
}
