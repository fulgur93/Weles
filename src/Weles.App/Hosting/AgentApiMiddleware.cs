using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http.Features;
using Weles.Infrastructure.Agents;

namespace Weles.App.Hosting;

/// <summary>
/// The agent endpoint (HTTPS, separate port). Requests arriving on that port are answered here and never reach the panel:
/// only the four <see cref="AgentProtocol"/> calls exist, everything else is 404. Requests on the panel port pass through
/// untouched (the panel has no agent routes).
/// </summary>
public sealed partial class AgentApiMiddleware(RequestDelegate next, AgentListenerState listener, AgentService agents, ILogger<AgentApiMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsAgentConnection(context))
        {
            await next(context);
            return;
        }

        context.Response.Headers.CacheControl = "no-store";
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit) limit.MaxRequestBodySize = AgentProtocol.MaxBodyBytes;
        var remote = context.Connection.RemoteIpAddress?.ToString() ?? "?";
        var path = context.Request.Path.Value ?? "";
        if (!HttpMethods.IsPost(context.Request.Method) || !path.StartsWith(AgentProtocol.Prefix + "/", StringComparison.Ordinal))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        try
        {
            if (path == AgentProtocol.EnrollPath)
            {
                var request = await ReadAsync<EnrollRequest>(context);
                await WriteAsync(context, request is null ? AgentCallResult<EnrollResponse>.Fail(400, "Nieprawidłowe żądanie.") : await agents.EnrollAsync(request, remote, context.RequestAborted));
                return;
            }

            var token = context.Request.Headers.Authorization.ToString() is { } header && header.StartsWith("Bearer ", StringComparison.Ordinal) ? header[7..].Trim() : null;
            var (agent, status) = await agents.AuthenticateAsync(token, remote, context.RequestAborted);
            if (agent is null)
            {
                context.Response.StatusCode = status;
                return;
            }

            if (path == AgentProtocol.HeartbeatPath)
            {
                var request = await ReadAsync<HeartbeatRequest>(context);
                await WriteAsync(context, request is null ? AgentCallResult<HeartbeatResponse>.Fail(400, "Nieprawidłowe żądanie.") : await agents.HeartbeatAsync(agent, request, remote, context.RequestAborted));
                return;
            }

            var match = ScanPath().Match(path);
            if (match.Success && int.TryParse(match.Groups[1].Value, out var scanId))
            {
                if (match.Groups[2].Value == "results")
                {
                    var request = await ReadAsync<ResultsRequest>(context);
                    await WriteAsync(context, request is null ? AgentCallResult<ResultsResponse>.Fail(400, "Nieprawidłowe żądanie.") : await agents.ResultsAsync(agent, scanId, request, remote, context.RequestAborted));
                }
                else
                {
                    var request = await ReadAsync<CompleteRequest>(context);
                    await WriteAsync(context, request is null ? AgentCallResult<ResultsResponse>.Fail(400, "Nieprawidłowe żądanie.") : await agents.CompleteAsync(agent, scanId, request, remote, context.RequestAborted));
                }

                return;
            }

            context.Response.StatusCode = StatusCodes.Status404NotFound;
        }
        catch (BadHttpRequestException ex)
        {
            logger.LogWarning("Agent request from {Remote} refused: {Error}", remote, ex.Message);
            context.Response.StatusCode = ex.StatusCode;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never the panel's error page on the agent port – a bare status, details only in the log.
            logger.LogError(ex, "Agent request {Path} from {Remote} failed", path, remote);
            if (!context.Response.HasStarted) context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        }
    }

    /// <summary>The connection came in on the agent endpoint (its address and port), not on the panel.</summary>
    private bool IsAgentConnection(HttpContext context) =>
        listener.IsListening && context.Connection.LocalPort == listener.Active.Port
        && context.Connection.LocalIpAddress is { } local && Normalize(local).Equals(IPAddress.Parse(listener.Active.Address));

    private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static async Task<T?> ReadAsync<T>(HttpContext context) where T : class
    {
        if (context.Request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) != true) return null;
        try
        {
            return await JsonSerializer.DeserializeAsync<T>(context.Request.Body, AgentProtocol.Json, context.RequestAborted);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static async Task WriteAsync<T>(HttpContext context, AgentCallResult<T> result) where T : class
    {
        context.Response.StatusCode = result.StatusCode;
        if (result.Body is not null) await context.Response.WriteAsJsonAsync(result.Body, AgentProtocol.Json, context.RequestAborted);
        else await context.Response.WriteAsJsonAsync(new { error = result.Error }, AgentProtocol.Json, context.RequestAborted);
    }

    [GeneratedRegex(@"^/agent-api/v1/scans/(\d{1,9})/(results|complete)$")]
    private static partial Regex ScanPath();

    /// <summary>
    /// Applies the saved settings at startup: the certificate (created once) and the HTTPS listener on the chosen
    /// address. A problem (port taken, address no longer on this computer) is reported in the UI instead of stopping WELES.
    /// </summary>
    public static AgentListenerState Configure(WebApplicationBuilder builder, Weles.Infrastructure.Platform.WelesPaths paths)
    {
        var settings = AgentListenerSettings.Load(paths);
        if (!settings.Enabled) return new AgentListenerState(settings, PinIfExists(paths), null);
        if (settings.Validate() is { } invalid) return new AgentListenerState(settings, PinIfExists(paths), invalid);

        var address = IPAddress.Parse(settings.Address);
        try
        {
            using var probe = new TcpListener(address, settings.Port);
            probe.Start();
            probe.Stop();
        }
        catch (SocketException ex)
        {
            var reason = ex.SocketErrorCode == SocketError.AddressAlreadyInUse
                ? $"Port {settings.Port} jest zajęty przez inny program."
                : $"Adres {settings.Address} nie należy już do tego komputera.";
            return new AgentListenerState(settings, PinIfExists(paths), reason);
        }

        var certificate = AgentCertificate.LoadOrCreate(paths, settings.Address);
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(address, settings.Port, listen => listen.UseHttps(certificate, https =>
            https.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13)));
        return new AgentListenerState(settings, AgentProtocol.Pin(certificate.RawData), null);
    }

    private static string? PinIfExists(Weles.Infrastructure.Platform.WelesPaths paths)
    {
        var file = Path.Combine(paths.KeysDirectory, AgentCertificate.FileName);
        if (!File.Exists(file)) return null;
        using var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(file, null);
        return AgentProtocol.Pin(certificate.RawData);
    }
}
