using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Weles.Core.Entities;
using Weles.Core.Enums;
using Weles.Core.External;
using Weles.Core.Rules;
using Weles.Infrastructure.External;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Core;
using Weles.Tests.Support;

namespace Weles.Tests.External;

public class DnsRecordParsingTests
{
    [Fact]
    public void Parses_mx_ns_cname_caa_and_response_flags()
    {
        var msg = DnsTestPackets.Response(7,
            DnsTestPackets.Record("firma.pl", DnsMessage.TypeMx, [0, 10, .. DnsTestPackets.Name("mail.firma.pl")]),
            DnsTestPackets.Record("firma.pl", DnsMessage.TypeNs, DnsTestPackets.Name("ns1.dns.pl")),
            DnsTestPackets.Record("www.firma.pl", DnsMessage.TypeCname, DnsTestPackets.Name("firma.pl")),
            DnsTestPackets.Record("firma.pl", DnsMessage.TypeCaa, [0, 5, .. "issue"u8.ToArray(), .. "letsencrypt.org"u8.ToArray()]));
        msg[3] |= 0x03; // NXDOMAIN
        msg[2] |= 0x02; // TC
        Assert.True(DnsMessage.TryParse(msg, out var id, out var rcode, out var truncated, out var records));
        Assert.Equal((7, DnsMessage.RcodeNameError, true), (id, rcode, truncated));
        Assert.Equal((ushort?)10, records[0].Preference);
        Assert.Equal("mail.firma.pl", records[0].Target);
        Assert.Equal("ns1.dns.pl", records[1].Target);
        Assert.Equal("firma.pl", records[2].Target);
        Assert.Equal(["issue", "letsencrypt.org"], records[3].Texts!);
        Assert.Equal(0x01, DnsMessage.BuildQuery(1, [("a.pl", DnsMessage.TypeA)], recursionDesired: true)[2]);
    }

    [Fact]
    public void Truncated_caa_is_ignored_without_throwing()
    {
        var msg = DnsTestPackets.Response(1, DnsTestPackets.Record("firma.pl", DnsMessage.TypeCaa, [0, 200, 1, 2]));
        Assert.True(DnsMessage.TryParse(msg, out _, out var records));
        Assert.Empty(records);
    }
}

public class DomainNameTests
{
    [Theory]
    [InlineData("Firma.PL.", "firma.pl")]
    [InlineData("*.sklep.firma.pl", "sklep.firma.pl")]
    [InlineData("żółw.pl", "xn--w-uga1v8h.pl")]
    public void Normalizes_public_domains(string input, string expected)
    {
        Assert.True(DomainNames.TryNormalize(input, out var domain, out var error), error);
        Assert.Equal(expected, domain);
    }

    [Theory]
    [InlineData("https://firma.pl/")]
    [InlineData("jan@firma.pl")]
    [InlineData("192.168.1.1")]
    [InlineData("nas.local")]
    [InlineData("router.lan")]
    [InlineData("localhost")]
    [InlineData("")]
    public void Rejects_urls_addresses_and_internal_names(string input) => Assert.False(DomainNames.TryNormalize(input, out _, out _));

    [Fact]
    public void Subdomain_check_and_untrusted_names()
    {
        Assert.True(DomainNames.IsWithin("a.b.firma.pl", "firma.pl"));
        Assert.False(DomainNames.IsWithin("zlafirma.pl", "firma.pl"));
        Assert.Equal("api.firma.pl", DomainNames.CleanHostName("*.API.firma.pl."));
        Assert.Null(DomainNames.CleanHostName("a*b.firma.pl"));
        Assert.Null(DomainNames.CleanHostName("<script>.firma.pl"));
        Assert.False(DomainNames.TryParsePublicAddress("10.0.0.1", out _, out _));
        Assert.True(DomainNames.TryParsePublicAddress("8.8.8.8", out _, out _));
    }
}

public class ExternalRulesTests
{
    private static ExternalSnapshot Snapshot(DnsRecordView[] records, ExternalHostView[]? hosts = null, string[]? wildcard = null) =>
        new("firma.pl", DateTime.UtcNow, ["127.0.0.1:53"], records, hosts ?? [], [], false, null, wildcard ?? [], 0, []);

    private static DnsRecordView R(string type, string value, string name = "firma.pl") => new(name, type, value, 300);

    private static string[] Codes(ExternalSnapshot s) => ExternalRules.Evaluate(s).Select(f => f.Code).ToArray();

    [Fact]
    public void Spf_and_dmarc_weaknesses()
    {
        Assert.Contains("SPF-PASS-ALL", Codes(Snapshot([R("MX", "10 mail.firma.pl"), R("TXT", "v=spf1 mx +all")])));
        Assert.Contains("SPF-NEUTRAL", Codes(Snapshot([R("TXT", "v=spf1 mx ?all")])));
        Assert.Contains("SPF-MULTIPLE", Codes(Snapshot([R("TXT", "v=spf1 mx -all"), R("TXT", "v=spf1 a -all")])));
        Assert.Contains("SPF-NO-ALL", Codes(Snapshot([R("TXT", "v=spf1 mx")])));
        Assert.Contains("SPF-LOOKUPS", Codes(Snapshot([R("TXT", "v=spf1 " + string.Join(' ', Enumerable.Range(1, 11).Select(i => $"include:s{i}.pl")) + " -all")])));
        var missing = ExternalRules.Evaluate(Snapshot([R("MX", "10 mail.firma.pl")]));
        Assert.Equal(RiskLevel.Medium, missing.Single(f => f.Code == "SPF-MISSING").Level);
        Assert.Equal(RiskLevel.Medium, missing.Single(f => f.Code == "DMARC-MISSING").Level);
        Assert.Contains("DMARC-NONE", Codes(Snapshot([R("TXT", "v=DMARC1; p=none; rua=mailto:d@firma.pl", "_dmarc.firma.pl")])));

        var good = Codes(Snapshot([R("MX", "10 mail.firma.pl"), R("TXT", "v=spf1 mx -all"), R("TXT", "v=DMARC1; p=reject", "_dmarc.firma.pl"),
            R("CAA", "0 issue \"letsencrypt.org\""), R("NS", "ns1.dns.pl"), R("NS", "ns2.dns.pl")]));
        Assert.Empty(good);
        // "v=spf10" or a TXT on another name is not SPF of the domain.
        Assert.Contains("SPF-MISSING", Codes(Snapshot([R("TXT", "v=spf10 x"), R("TXT", "v=spf1 -all", "www.firma.pl")])));
    }

    [Fact]
    public void Host_findings_quote_their_evidence()
    {
        var findings = ExternalRules.Evaluate(Snapshot([R("NS", "ns1.firma.pl")],
        [
            new("old.firma.pl", [], "gone.herokuapp.com", false, true, false, ["CT"]),
            new("intranet.firma.pl", ["10.1.2.3"], null, true, false, false, ["CT"]),
            new("vpn-gw.firma.pl", ["93.184.216.40"], null, true, false, false, ["CT"]),
            new("admin.firma.pl", ["93.184.216.99"], null, true, false, true, ["CT"]),   // wildcard answer – not reported
            new("www.firma.pl", ["93.184.216.34"], null, true, false, false, ["CT"])
        ], ["93.184.216.99"]));
        var dangling = findings.Single(f => f.Code == "DANGLING-CNAME");
        Assert.Equal((RiskLevel.High, "old.firma.pl → gone.herokuapp.com (NXDOMAIN)"), (dangling.Level, dangling.Evidence));
        Assert.Contains(findings, f => f.Code == "DNS-PRIVATE-ADDRESS" && f.Evidence.Contains("10.1.2.3"));
        Assert.Equal(["intranet.firma.pl", "vpn-gw.firma.pl"], findings.Where(f => f.Code == "ADMIN-NAME").Select(f => f.Host!).Order().ToArray());
        Assert.Contains(findings, f => f.Code == "NS-SINGLE");
        Assert.Contains(findings, f => f.Code == "DNS-WILDCARD");
        Assert.Equal(RiskLevel.High, findings[0].Level);
    }

    [Fact]
    public void Address_target_gets_no_mail_findings()
    {
        var s = new ExternalSnapshot("8.8.8.8", DateTime.UtcNow, [], [R("PTR", "dns.google", "8.8.8.8")], [new("8.8.8.8", ["8.8.8.8"], null, true, false, false, ["użytkownik"])], [], false, null, [], 0, []);
        Assert.Empty(ExternalRules.Evaluate(s));
    }
}

public class ExternalSurfaceServiceTests
{
    /// <summary>Authoritative-like DNS on 127.0.0.1 answering from a fixed zone – the test never leaves this machine.</summary>
    private sealed class FakeDns : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly Dictionary<(string, ushort), (int Rcode, byte[][] Answers)> _zone = new();
        public List<string> Asked { get; } = [];

        public FakeDns()
        {
            _ = Task.Run(LoopAsync);
        }

        public IPEndPoint EndPoint => (IPEndPoint)_udp.Client.LocalEndPoint!;

        public void Add(string name, ushort type, params byte[][] answers) => _zone[(name, type)] = (0, answers);
        public void NxDomain(string name, ushort type, params byte[][] answers) => _zone[(name, type)] = (3, answers);

        private async Task LoopAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                UdpReceiveResult packet;
                try { packet = await _udp.ReceiveAsync(_stop.Token); } catch { return; }
                var q = packet.Buffer;
                var offset = 12;
                var name = DnsMessage.ReadName(q, ref offset);
                var type = BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(offset));
                lock (Asked) Asked.Add($"{name}/{DnsMessage.TypeName(type)}");
                var known = _zone.Keys.Any(k => k.Item1 == name);
                var (rcode, answers) = _zone.TryGetValue((name, type), out var hit) ? hit : (known ? 0 : 3, Array.Empty<byte[]>());
                var response = DnsTestPackets.Response(BinaryPrimitives.ReadUInt16BigEndian(q), answers);
                response[3] = (byte)(0x80 | rcode);
                await _udp.SendAsync(response, packet.RemoteEndPoint);
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _udp.Dispose();
        }
    }

    private sealed class FakeCt(params CtCertificateView[] certificates) : ICertificateTransparencySource
    {
        public int Calls { get; private set; }

        public Task<CtResult> SearchAsync(string domain, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(new CtResult(certificates, null));
        }
    }

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }

    private static byte[] A(string name, string ip) => DnsTestPackets.A(name, ip);
    private static byte[] Name(string name, ushort type, string target) => DnsTestPackets.Record(name, type, DnsTestPackets.Name(target));

    [Fact]
    public async Task Passive_analysis_collects_dns_and_ct_and_prepares_an_unapproved_public_scope()
    {
        const string d = "weles-test.pl";
        using var dns = new FakeDns();
        dns.Add(d, DnsMessage.TypeA, A(d, "93.184.216.34"));
        dns.Add(d, DnsMessage.TypeMx, DnsTestPackets.Record(d, DnsMessage.TypeMx, [0, 10, .. DnsTestPackets.Name("mail." + d)]));
        dns.Add(d, DnsMessage.TypeNs, Name(d, DnsMessage.TypeNs, "ns1." + d));
        dns.Add(d, DnsMessage.TypeTxt, DnsTestPackets.Txt(d, "v=spf1 mx +all"), DnsTestPackets.Txt(d, "google-site-verification=abc"));
        dns.Add(d, DnsMessage.TypeSoa, Name(d, DnsMessage.TypeSoa, "ns1." + d));
        dns.Add("mail." + d, DnsMessage.TypeA, A("mail." + d, "93.184.216.35"));
        dns.Add("ns1." + d, DnsMessage.TypeA, A("ns1." + d, "93.184.216.36"));
        dns.Add("www." + d, DnsMessage.TypeA, Name("www." + d, DnsMessage.TypeCname, d), A(d, "93.184.216.34"));
        dns.Add("intranet." + d, DnsMessage.TypeA, A("intranet." + d, "10.1.2.3"));
        dns.NxDomain("old." + d, DnsMessage.TypeA, Name("old." + d, DnsMessage.TypeCname, "gone.example-cloud.net"));

        var ct = new FakeCt(new CtCertificateView(1, "www." + d, ["www." + d, d], "C=US, O=Let's Encrypt, CN=R11", DateTime.UtcNow.AddDays(-10), DateTime.UtcNow.AddDays(80)),
            new CtCertificateView(2, "old." + d, ["old." + d, "intranet." + d], "C=US, O=Let's Encrypt, CN=R3", DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddYears(-2).AddDays(90)));

        await using var db = await TestDatabase.CreateAsync();
        var options = Options.Create(new ExternalOptions { DnsServers = [dns.EndPoint.ToString()], DnsTimeoutMs = 1500 });
        var scopes = new ScanTargetService(db, new ScanCoordinator(TimeProvider.System), Options.Create(new ScanOptions()), TimeProvider.System, NullLogger<ScanTargetService>.Instance);
        var service = new ExternalSurfaceService(db, new DnsLookup(options), ct, scopes, options, TimeProvider.System, new Lifetime(), NullLogger<ExternalSurfaceService>.Instance);

        Assert.False((await service.AddAsync(new ExternalTargetInput(d, null, ConfirmedAuthorization: false, true, null))).Success);
        Assert.False((await service.AddAsync(new ExternalTargetInput(d, null, true, true, "www.innafirma.pl"))).Success);
        var added = await service.AddAsync(new ExternalTargetInput(d.ToUpperInvariant(), "test", true, true, "www." + d));
        Assert.True(added.Success, string.Join(", ", added.Errors));
        var id = added.Id!.Value;
        Assert.False((await service.AddAsync(new ExternalTargetInput(d, null, true, true, null))).Success);   // duplicate

        Assert.True((await service.StartPassiveAsync(id)).Success);
        await service.WaitAsync(id);
        var view = await service.AnalysisAsync(id);
        Assert.NotNull(view?.Snapshot);
        var s = view.Snapshot;
        Assert.Equal(ExternalAnalysisStatus.Completed, view.Analysis.Status);
        Assert.Equal(1, ct.Calls);

        Assert.Contains(s.Records, r => r.Type == "MX" && r.Value == "10 mail." + d);
        Assert.Contains(s.Records, r => r.Type == "TXT" && r.Value == "v=spf1 mx +all");
        Assert.Empty(s.WildcardAddresses);
        var hosts = s.Hosts.ToDictionary(h => h.Name);
        Assert.Equal(new[] { d, "intranet." + d, "mail." + d, "ns1." + d, "old." + d, "www." + d }.Order(StringComparer.Ordinal), hosts.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(d, hosts["www." + d].Cname);
        Assert.Contains("użytkownik", hosts["www." + d].Sources);
        Assert.Contains("CT", hosts["www." + d].Sources);
        Assert.True(hosts["old." + d].DanglingCname);
        Assert.Equal(["MX"], hosts["mail." + d].Sources);

        var codes = view.Findings.Select(f => f.Code).ToHashSet();
        foreach (var code in new[] { "SPF-PASS-ALL", "DMARC-MISSING", "NS-SINGLE", "DANGLING-CNAME", "DNS-PRIVATE-ADDRESS", "ADMIN-NAME", "CAA-MISSING" }) Assert.Contains(code, codes);
        // Only names from authorised sources were asked – nothing guessed.
        Assert.DoesNotContain(dns.Asked, q => q.StartsWith("api.") || q.StartsWith("dev."));

        // Active scanning: only names pointing to public addresses; the scope is created unapproved, with public permission.
        Assert.False((await service.PrepareActiveScopeAsync(id, ["intranet." + d])).Success);
        Assert.False((await service.PrepareActiveScopeAsync(id, ["inna.pl"])).Success);
        var prepared = await service.PrepareActiveScopeAsync(id, ["www." + d, d]);
        Assert.True(prepared.Success, string.Join(", ", prepared.Errors));
        await using (var ctx = db.CreateDbContext())
        {
            var scope = await ctx.ScanTargets.Include(t => t.Entries).SingleAsync(t => t.Id == prepared.Id);
            Assert.False(scope.IsApproved);
            Assert.True(scope.AllowPublicAddresses);
            Assert.Equal([d, "www." + d], scope.Entries.Select(e => e.Value).Order().ToArray());
        }

        Assert.True((await scopes.ApproveAsync(prepared.Id!.Value, true)).Success);
        var again = await service.PrepareActiveScopeAsync(id, ["mail." + d]);
        Assert.Equal(prepared.Id, again.Id);   // the same scope is reused…
        Assert.Contains((await scopes.ListAsync()), t => t.Id == again.Id && !t.IsApproved);   // …and changing it revokes approval
        Assert.Null(await service.ActiveResultAsync(id));

        // Deleting the target keeps the scope (audit history).
        Assert.True((await service.DeleteAsync(id)).Success);
        Assert.Contains(await scopes.ListAsync(), t => t.Id == again.Id);
    }

    [Fact]
    public async Task Unreachable_dns_fails_the_analysis_with_a_reason()
    {
        // A local port with nothing listening: queries time out quickly.
        using var placeholder = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = placeholder.Client.LocalEndPoint!.ToString()!;
        placeholder.Dispose();
        await using var db = await TestDatabase.CreateAsync();
        var options = Options.Create(new ExternalOptions { DnsServers = [endpoint], DnsTimeoutMs = 200 });
        var scopes = new ScanTargetService(db, new ScanCoordinator(TimeProvider.System), Options.Create(new ScanOptions()), TimeProvider.System, NullLogger<ScanTargetService>.Instance);
        var service = new ExternalSurfaceService(db, new DnsLookup(options), new FakeCt(), scopes, options, TimeProvider.System, new Lifetime(), NullLogger<ExternalSurfaceService>.Instance);
        var id = (await service.AddAsync(new ExternalTargetInput("weles-test.pl", null, true, false, null))).Id!.Value;
        await service.StartPassiveAsync(id);
        await service.WaitAsync(id);
        var view = await service.AnalysisAsync(id);
        Assert.Equal(ExternalAnalysisStatus.Failed, view!.Analysis.Status);
        Assert.Equal("Brak odpowiedzi serwerów DNS.", view.Analysis.Error);
    }
}
