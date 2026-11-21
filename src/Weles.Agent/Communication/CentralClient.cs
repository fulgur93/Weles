using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Authentication;
using Weles.Infrastructure.Agents;

namespace Weles.Agent.Communication;

/// <summary>WELES refused the call; <see cref="StatusCode"/> 401 means the token is invalid or the agent was revoked.</summary>
public sealed class CentralException(HttpStatusCode statusCode, string message) : Exception(message)
{
    public HttpStatusCode StatusCode { get; } = statusCode;
}

/// <summary>
/// HTTPS client of the WELES agent endpoint. The server certificate is accepted only when its SHA-256 equals the pin
/// given at enrollment – no CA, no hostname check, nothing else is trusted. Only HTTPS URLs are allowed; TLS 1.2+.
/// </summary>
public sealed class CentralClient : IDisposable
{
    private readonly HttpClient _http;

    public CentralClient(string server, string pin, string? token = null, HttpMessageHandler? handler = null)
    {
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Adres serwera WELES musi zaczynać się od https://", nameof(server));
        var expected = AgentProtocol.NormalizePin(pin);
        if (expected.Length != 64) throw new ArgumentException("Odcisk certyfikatu (SHA-256) musi mieć 64 znaki szesnastkowe.", nameof(pin));

        handler ??= new SocketsHttpHandler
        {
            SslOptions =
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    certificate is not null && AgentProtocol.Pin(certificate.GetRawCertData()) == expected
            },
            ConnectTimeout = TimeSpan.FromSeconds(15),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        };
        _http = new HttpClient(handler) { BaseAddress = new Uri(uri.GetLeftPart(UriPartial.Authority)), Timeout = TimeSpan.FromSeconds(60) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("WELES-agent/1.0");
        if (token is not null) _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken ct) => PostAsync<EnrollRequest, EnrollResponse>(AgentProtocol.EnrollPath, request, ct);

    public Task<HeartbeatResponse> HeartbeatAsync(HeartbeatRequest request, CancellationToken ct) => PostAsync<HeartbeatRequest, HeartbeatResponse>(AgentProtocol.HeartbeatPath, request, ct);

    public Task<ResultsResponse> ResultsAsync(int scanId, ResultsRequest request, CancellationToken ct) => PostAsync<ResultsRequest, ResultsResponse>(AgentProtocol.ResultsPath(scanId), request, ct);

    public Task<ResultsResponse> CompleteAsync(int scanId, CompleteRequest request, CancellationToken ct) => PostAsync<CompleteRequest, ResultsResponse>(AgentProtocol.CompletePath(scanId), request, ct);

    private async Task<TResponse> PostAsync<TRequest, TResponse>(string path, TRequest request, CancellationToken ct)
    {
        using var response = await _http.PostAsJsonAsync(path, request, AgentProtocol.Json, ct);
        if (!response.IsSuccessStatusCode)
        {
            string? error = null;
            try
            {
                error = (await response.Content.ReadFromJsonAsync<ErrorBody>(AgentProtocol.Json, ct))?.Error;
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or NotSupportedException or HttpRequestException)
            {
                // No JSON body (e.g. 401, 404).
            }

            throw new CentralException(response.StatusCode, error ?? $"WELES odpowiedział kodem {(int)response.StatusCode}.");
        }

        return await response.Content.ReadFromJsonAsync<TResponse>(AgentProtocol.Json, ct)
               ?? throw new CentralException(response.StatusCode, "Pusta odpowiedź WELES.");
    }

    private sealed record ErrorBody(string? Error);

    public void Dispose() => _http.Dispose();
}
