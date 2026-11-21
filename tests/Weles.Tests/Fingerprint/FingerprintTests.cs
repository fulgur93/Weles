using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.Fingerprint;
using Weles.Infrastructure.Fingerprint;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Support;

namespace Weles.Tests.Fingerprint;

public class FingerprintTests
{
    private static readonly byte[] Icon = Enumerable.Range(0, 300).Select(i => (byte)(i * 7)).ToArray();

    /// <summary>A small WordPress-like site: "/" redirects, the page sets cookies, wp-login exists, everything else is 404.</summary>
    private static FakeServer WordPressSite() => new(async (stream, ct) =>
    {
        var buffer = new byte[4096];
        var read = await stream.ReadAsync(buffer, ct);
        var request = Encoding.ASCII.GetString(buffer, 0, read);
        var path = request.Split(' ')[1];
        byte[] Response(string status, string headers, byte[] body) =>
            [.. Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\n{headers}Content-Length: {body.Length}\r\nConnection: close\r\n\r\n"), .. body];
        var reply = path switch
        {
            "/" => Response("302 Found", "Location: /blog/\r\n", []),
            "/blog/" => Response("200 OK",
                "Server: nginx/1.24.0\r\nX-Powered-By: PHP/8.1.2\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/\r\nSet-Cookie: PHPSESSID=abc; path=/; HttpOnly; SameSite=Lax\r\nLink: <http://x/wp-json/>; rel=\"https://api.w.org/\"\r\n",
                Encoding.UTF8.GetBytes("<html><head><title>Blog testowy</title><meta name=\"generator\" content=\"WordPress 6.4.2\" /><link href=\"/wp-content/themes/x/style.css\"></head><body>Witaj</body></html>")),
            "/favicon.ico" => Response("200 OK", "Content-Type: image/x-icon\r\n", Icon),
            "/wp-login.php" => Response("200 OK", "Content-Type: text/html\r\n", Encoding.UTF8.GetBytes("<title>Log In</title><form><input name=\"user_login\"><input type=\"submit\" id=\"wp-submit\"></form>")),
            _ => Response("404 Not Found", "Content-Type: text/html\r\n", Encoding.UTF8.GetBytes("<title>404</title>"))
        };
        await stream.WriteAsync(reply, ct);
    });

    [Fact]
    public void Built_in_signatures_are_valid_and_favicon_hashes_match_the_common_format()
    {
        Assert.True(SignatureEngine.BuiltIn.Count >= 50);
        Assert.Equal(SignatureEngine.BuiltIn.Count, SignatureEngine.BuiltIn.Select(s => s.Id).Distinct().Count());
        Assert.All(Enum.GetValues<SignatureCategory>().Where(c => c != SignatureCategory.Other), c => Assert.Contains(SignatureEngine.BuiltIn, s => s.Category == c));
        // Reference values computed independently (MurmurHash3 x86_32, seed 0) – the hash Shodan and fingerprint lists use.
        Assert.Equal(613153351, FaviconHash.Murmur3("hello"u8.ToArray()));
        Assert.Equal(776992547, FaviconHash.Murmur3("The quick brown fox jumps over the lazy dog"u8.ToArray()));
        Assert.All(SignatureEngine.PathsOf(SignatureEngine.BuiltIn), p => Assert.True(SignatureEngine.IsSafePath(p)));
    }

    [Fact]
    public void Custom_signatures_are_validated_and_cannot_hang_the_scanner()
    {
        Signature S(params SignatureCondition[] c) => new("moja-aplikacja", "Moja aplikacja", SignatureCategory.Other, c);
        Assert.Empty(SignatureEngine.Validate(S(new SignatureCondition("header", Name: "X-App"))));
        Assert.NotEmpty(SignatureEngine.Validate(S(new SignatureCondition("header"))));                            // no header name
        Assert.NotEmpty(SignatureEngine.Validate(S(new SignatureCondition("body", Pattern: "(unclosed"))));       // invalid regex
        Assert.NotEmpty(SignatureEngine.Validate(S(new SignatureCondition("path", Path: "/login?user=admin&pass=admin")))); // nothing is submitted
        Assert.NotEmpty(SignatureEngine.Validate(S(new SignatureCondition("path", Path: "/../etc/passwd"))));
        Assert.NotEmpty(SignatureEngine.Validate(S(new SignatureCondition("exploit", Pattern: "x"))));            // unknown type
        Assert.NotEmpty(SignatureEngine.Validate(S() with { Id = "Złe ID!" }));

        // Catastrophic backtracking is cut off by the regex timeout instead of blocking the scan.
        var evil = S(new SignatureCondition("body", Pattern: "^(a+)+$"));
        var web = new WebObservation("http://x/", 200, null, new Dictionary<string, string>(), [], [], new string('a', 40) + "!", null, null, []);
        var watch = Stopwatch.StartNew();
        Assert.Empty(SignatureEngine.Evaluate(web, [evil]));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task The_scanner_records_the_web_service_and_signatures_recognise_it()
    {
        await using var site = WordPressSite();
        var prober = new ServiceProber(new ScanOptions { ConnectTimeoutMs = 800, BannerTimeoutMs = 300, ProbeTimeoutMs = 1500 });
        var result = await prober.ProbeAsync(IPAddress.Loopback, site.Port, null, CancellationToken.None);
        var web = result.Identification.Web;
        Assert.NotNull(web);
        Assert.Equal($"http://127.0.0.1:{site.Port}/blog/", web.Url);
        Assert.Equal(200, web.Status);
        Assert.Equal("Blog testowy", web.Title);
        Assert.Equal(["302 → /blog/"], web.Redirects);
        Assert.Equal("PHP/8.1.2", web.Header("x-powered-by"));
        var session = Assert.Single(web.Cookies, c => c.Name == "PHPSESSID");
        Assert.True(session.HttpOnly);
        Assert.False(session.Secure);
        Assert.Equal("Lax", session.SameSite);
        Assert.False(web.Cookies.Single(c => c.Name == "wordpress_test_cookie").HttpOnly);
        Assert.DoesNotContain(JsonSerializer.Serialize(web), "Cookie%20check"); // cookie values are never stored
        Assert.Equal(FaviconHash.Mmh3(Icon), web.FaviconMmh3);
        Assert.Equal(200, web.Paths.Single(p => p.Path == "/wp-login.php").Status);
        Assert.Equal(404, web.Paths.Single(p => p.Path == "/admin").Status);

        var found = SignatureEngine.Evaluate(web, SignatureEngine.BuiltIn);
        var wordpress = Assert.Single(found, m => m.Name == "WordPress");
        Assert.Equal("6.4.2", wordpress.Version);
        Assert.True(wordpress.Confidence > 85);              // several independent conditions
        Assert.Equal("8.1.2", found.Single(m => m.Name == "PHP").Version);
        Assert.Equal("1.24.0", found.Single(m => m.Name == "nginx").Version);
        Assert.Contains(found, m => m.Category == SignatureCategory.AdminPanel && m.SignatureId == "wp-admin");
        Assert.DoesNotContain(found, m => m.Name == "Joomla!");

        // A custom favicon signature matches the same service.
        var custom = new Signature("moj-favicon", "Aplikacja wewnętrzna", SignatureCategory.Other, [new SignatureCondition("favicon", Hash: FaviconHash.Mmh3(Icon))]);
        Assert.Single(SignatureEngine.Evaluate(web, [custom]));
    }

    [Fact]
    public async Task Custom_signatures_apply_to_stored_scans_without_scanning_again()
    {
        await using var db = await TestDatabase.CreateAsync();
        var target = TestData.ApprovedTarget();
        var web = new WebObservation("http://10.0.0.5:8080/", 200, "Panel ACME", new Dictionary<string, string> { ["X-Acme-App"] = "4.2" }, [], [], "<html>acme</html>", null, null, []);
        int serviceId;
        await using (var ctx = db.CreateDbContext())
        {
            var scan = TestData.CompletedScan(target, TestData.Now);
            var host = new DiscoveredHost { Scan = scan, IpAddress = "10.0.0.5", DiscoveredAt = TestData.Now };
            var stored = new DiscoveredService { ServiceName = "http", Confidence = 70, WebJson = JsonSerializer.Serialize(web, SignatureEngine.Json) };
            host.Ports.Add(new DiscoveredPort { Port = 8080, State = PortState.Open, Service = stored });
            ctx.DiscoveredHosts.Add(host);
            await ctx.SaveChangesAsync();
            serviceId = stored.Id;
        }

        var service = new SignatureService(db, TimeProvider.System, NullLogger<SignatureService>.Instance);
        var json = """{ "id": "acme", "name": "ACME Panel", "category": "adminPanel", "conditions": [ { "type": "header", "name": "X-Acme-App" } ], "version": { "source": "header:X-Acme-App", "pattern": "([0-9.]+)" } }""";
        var tested = await service.TestAsync(SignatureService.Parse(json, out _)!);
        Assert.Equal(8080, Assert.Single(tested).Port);

        Assert.True((await service.SaveAsync(json, "admin")).Success);
        await using (var ctx = db.CreateDbContext())
        {
            var tech = await ctx.ServiceTechnologies.SingleAsync(t => t.DiscoveredServiceId == serviceId && t.SignatureId == "acme");
            Assert.Equal("4.2", tech.Version);
            Assert.Equal(SignatureCategory.AdminPanel, tech.Category);
        }

        // Built-in ids are protected; an import reports the invalid entries and stores the valid ones.
        Assert.False((await service.SaveAsync("""{ "id": "wordpress", "name": "x", "category": "cms", "conditions": [ { "type": "body", "pattern": "x" } ] }""", null)).Success);
        var (saved, errors) = await service.ImportAsync("""[ { "id": "ok-one", "name": "OK", "category": "other", "conditions": [ { "type": "title", "pattern": "Panel" } ] }, { "id": "bad", "name": "Bad", "category": "other", "conditions": [] } ]""", null);
        Assert.Equal(1, saved);
        Assert.Single(errors);
        Assert.Equal(2, (await service.CustomAsync()).Count);

        var acme = (await service.CustomAsync()).Single(c => c.Signature!.Id == "acme");
        await service.SetEnabledAsync(acme.Id, false);
        await using (var ctx = db.CreateDbContext())
        {
            Assert.False(await ctx.ServiceTechnologies.AnyAsync(t => t.SignatureId == "acme"));
            Assert.True(await ctx.ServiceTechnologies.AnyAsync(t => t.SignatureId == "ok-one"));
        }

        Assert.Contains("ok-one", await service.ExportAsync());
    }
}
