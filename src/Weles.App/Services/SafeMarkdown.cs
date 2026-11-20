using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components;

namespace Weles.App.Services;

/// <summary>
/// Renders the analyst's answer: a small Markdown subset (headings, lists, bold, inline code, paragraphs). Everything is
/// HTML-encoded first, so model output can never inject markup or scripts; no external links are produced – only CVE IDs
/// become links to the local CVE page.
/// </summary>
public static partial class SafeMarkdown
{
    public static MarkupString Render(string? text)
    {
        if (string.IsNullOrEmpty(text)) return new MarkupString("");
        var html = new StringBuilder();
        string? list = null;
        var paragraph = new List<string>();

        void FlushParagraph()
        {
            if (paragraph.Count == 0) return;
            html.Append("<p>").Append(string.Join("<br>", paragraph)).Append("</p>");
            paragraph.Clear();
        }

        void CloseList()
        {
            if (list is null) return;
            html.Append($"</{list}>");
            list = null;
        }

        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.Trim().Length == 0)
            {
                FlushParagraph();
                CloseList();
                continue;
            }

            if (HeadingRx().Match(line) is { Success: true } h)
            {
                FlushParagraph();
                CloseList();
                var level = Math.Min(6, h.Groups[1].Value.Length + 2);
                html.Append($"<h{level}>{Inline(h.Groups[2].Value)}</h{level}>");
                continue;
            }

            var bullet = BulletRx().Match(line);
            var number = NumberRx().Match(line);
            if (bullet.Success || number.Success)
            {
                FlushParagraph();
                var kind = bullet.Success ? "ul" : "ol";
                if (list != kind)
                {
                    CloseList();
                    html.Append($"<{kind}>");
                    list = kind;
                }

                html.Append("<li>").Append(Inline(bullet.Success ? bullet.Groups[1].Value : number.Groups[1].Value)).Append("</li>");
                continue;
            }

            CloseList();
            paragraph.Add(Inline(line.Trim()));
        }

        FlushParagraph();
        CloseList();
        return new MarkupString(html.ToString());
    }

    private static string Inline(string text)
    {
        var s = WebUtility.HtmlEncode(text);
        s = CodeRx().Replace(s, "<code>$1</code>");
        s = BoldRx().Replace(s, "<strong>$1</strong>");
        s = CveRx().Replace(s, m => $"<a href=\"vulnerabilities/{m.Value.ToUpperInvariant()}\">{m.Value}</a>");
        return s;
    }

    [GeneratedRegex(@"^\s{0,3}(#{1,4})\s+(.+)$")] private static partial Regex HeadingRx();
    [GeneratedRegex(@"^\s*[-*•]\s+(.+)$")] private static partial Regex BulletRx();
    [GeneratedRegex(@"^\s*\d{1,2}[.)]\s+(.+)$")] private static partial Regex NumberRx();
    [GeneratedRegex(@"`([^`]+)`")] private static partial Regex CodeRx();
    [GeneratedRegex(@"\*\*(.+?)\*\*")] private static partial Regex BoldRx();
    [GeneratedRegex(@"\bCVE-\d{4}-\d{4,}\b", RegexOptions.IgnoreCase)] private static partial Regex CveRx();
}
