using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Vulnerabilities;
using Weles.Infrastructure.Vulnerabilities;

// Builds the vulnerability snapshot bundled with WELES:
//   dotnet run --project tools/Weles.VulnDbBuilder -- <output.json.gz>
// Optional NVD API key in the environment variable NVD_API_KEY (faster; never written to the output).
if (args.Length != 1)
{
    Console.Error.WriteLine("Użycie: Weles.VulnDbBuilder <plik-wyjściowy.json.gz>");
    return 2;
}

using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(LogLevel.Information));
var log = loggerFactory.CreateLogger("VulnDbBuilder");
var options = Options.Create(new VulnerabilityFeedOptions { NvdApiKey = Environment.GetEnvironmentVariable("NVD_API_KEY") });
using var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
http.DefaultRequestHeaders.UserAgent.ParseAdd("WELES-vulnerability-feed/1.0");
var feeds = new VulnerabilityFeedClient(http, options, loggerFactory.CreateLogger<VulnerabilityFeedClient>());

var createdAt = DateTime.UtcNow;
var records = new Dictionary<string, VulnerabilityRecord>(StringComparer.OrdinalIgnoreCase);
var queries = VulnerabilityFeedClient.CatalogQueries();
for (var i = 0; i < queries.Count; i++)
{
    var before = records.Count;
    await foreach (var page in feeds.NvdAsync(queries[i], null, null, CancellationToken.None))
    {
        foreach (var r in page) records[r.CveId] = r;
    }

    log.LogInformation("NVD {Index}/{Total} {Query}: +{New} (razem {Count})", i + 1, queries.Count, queries[i], records.Count - before, records.Count);
}

var kev = await feeds.KevAsync(CancellationToken.None);
var epss = await feeds.EpssAsync(records.ContainsKey, CancellationToken.None);
log.LogInformation("KEV {Version}: {Count} wpisów; EPSS {Date:yyyy-MM-dd}: {Epss} wyników dla CVE z bazy", kev.Version, kev.Entries.Count, epss.ScoreDate, epss.Entries.Count);

var snapshot = new VulnerabilitySnapshot
{
    CreatedAt = createdAt,
    NvdQueries = queries,
    KevVersion = kev.Version,
    KevReleasedAt = kev.ReleasedAt,
    EpssScoreDate = epss.ScoreDate,
    EpssModelVersion = epss.ModelVersion,
    Vulnerabilities = records.Values.OrderBy(r => r.CveId, StringComparer.Ordinal).ToList(),
    Kev = kev.Entries.Where(k => records.ContainsKey(k.CveId)).OrderBy(k => k.CveId, StringComparer.Ordinal).ToList(),
    Epss = epss.Entries.OrderBy(e => e.CveId, StringComparer.Ordinal).ToList()
};

var output = Path.GetFullPath(args[0]);
var temp = output + ".tmp";
await using (var file = File.Create(temp))
{
    await snapshot.WriteAsync(file);
}

File.Move(temp, output, overwrite: true);
log.LogInformation("Zapisano {Path}: {Count} CVE, {Kev} w KEV, {Size:0.0} MB", output, snapshot.Vulnerabilities.Count, snapshot.Kev.Count, new FileInfo(output).Length / 1048576.0);
return 0;
