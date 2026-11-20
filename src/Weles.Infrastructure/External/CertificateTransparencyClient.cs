using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.External;

namespace Weles.Infrastructure.External;

public sealed record CtResult(IReadOnlyList<CtCertificateView> Certificates, string? Error);

public interface ICertificateTransparencySource
{
    /// <summary>Certificates logged for the domain and its subdomains. Sends only the domain name to the public log service.</summary>
    Task<CtResult> SearchAsync(string domain, CancellationToken ct);
}

/// <summary>
/// Certificate Transparency search through crt.sh. CT logs are public by design: every publicly trusted certificate is
/// logged there, so the names in them are an authorised, passive source of subdomains. Responses are untrusted input.
/// </summary>
public sealed class CertificateTransparencyClient(IHttpClientFactory httpFactory, IOptions<ExternalOptions> options, ILogger<CertificateTransparencyClient> logger) : ICertificateTransparencySource
{
    public const string HttpClientName = "certificate-transparency";
    private const int MaxEntries = 20_000;

    /// <summary>Pause before a retry (multiplied by the attempt number); tests set it to 0.</summary>
    internal static double RetryDelaySeconds { get; set; } = 3;

    public async Task<CtResult> SearchAsync(string domain, CancellationToken ct)
    {
        var o = options.Value;
        var url = $"{o.CertificateTransparencyUrl.TrimEnd('/')}/?q={Uri.EscapeDataString("%." + domain)}&output=json";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(o.CertificateTransparencyTimeoutSeconds));
        var http = httpFactory.CreateClient(HttpClientName);
        try
        {
            // crt.sh is often overloaded (502/503/504/429) – two more attempts after a pause before giving up.
            var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            for (var attempt = 1; attempt <= 2 && (int)response.StatusCode is 429 or 502 or 503 or 504; attempt++)
            {
                response.Dispose();
                await Task.Delay(TimeSpan.FromSeconds(RetryDelaySeconds * attempt), timeout.Token);
                response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            }

            using var _ = response;
            if (!response.IsSuccessStatusCode)
            {
                return new CtResult([], $"crt.sh odpowiedział kodem {(int)response.StatusCode} – spróbuj ponownie później.");
            }

            if (response.Content.Headers.ContentLength > o.CertificateTransparencyMaxBytes)
            {
                return new CtResult([], "Odpowiedź crt.sh jest zbyt duża dla tej domeny.");
            }

            await using var stream = new LimitedStream(await response.Content.ReadAsStreamAsync(timeout.Token), o.CertificateTransparencyMaxBytes);
            var certificates = new List<CtCertificateView>();
            await foreach (var e in JsonSerializer.DeserializeAsyncEnumerable<CtEntry>(stream, cancellationToken: timeout.Token))
            {
                if (e is null) continue;
                if (certificates.Count >= MaxEntries) break;
                var names = (e.NameValue ?? "").Split('\n').Append(e.CommonName ?? "")
                    .Select(DomainNames.CleanHostName).OfType<string>()
                    .Where(n => DomainNames.IsWithin(n, domain)).Distinct().Take(100).ToList();
                if (names.Count == 0) continue;
                certificates.Add(new CtCertificateView(e.Id, Clip(e.CommonName, 253), names, Clip(e.IssuerName, 300), Date(e.NotBefore), Date(e.NotAfter)));
            }

            return new CtResult(certificates, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new CtResult([], "crt.sh nie odpowiedział w wyznaczonym czasie – spróbuj ponownie później.");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or IOException)
        {
            logger.LogWarning("Certificate Transparency query failed: {Error}", ex.Message);
            return new CtResult([], "Nie udało się pobrać danych z crt.sh (brak połączenia lub nieprawidłowa odpowiedź).");
        }
    }

    private static string Clip(string? s, int max) => s is null ? "" : s.Length <= max ? s : s[..max];

    private static DateTime Date(string? s) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : DateTime.MinValue;

    private sealed class CtEntry
    {
        [JsonPropertyName("id")] public long Id { get; set; }
        [JsonPropertyName("issuer_name")] public string? IssuerName { get; set; }
        [JsonPropertyName("common_name")] public string? CommonName { get; set; }
        [JsonPropertyName("name_value")] public string? NameValue { get; set; }
        [JsonPropertyName("not_before")] public string? NotBefore { get; set; }
        [JsonPropertyName("not_after")] public string? NotAfter { get; set; }
    }

    /// <summary>Stops reading after a byte limit – a huge or endless response cannot exhaust memory.</summary>
    private sealed class LimitedStream(Stream inner, long limit) : Stream
    {
        private long _read;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _read; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Count(inner.Read(buffer, offset, count));
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => Count(await inner.ReadAsync(buffer, ct));
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }

        private int Count(int n)
        {
            _read += n;
            if (_read > limit) throw new IOException("Response too large");
            return n;
        }
    }
}
