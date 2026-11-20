using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Interfaces;
using Weles.Core.Models;

namespace Weles.Infrastructure.AI;

/// <summary>Ollama implementation of <see cref="IAiService"/> using its local HTTP API.</summary>
public sealed class OllamaAiService(HttpClient httpClient, IOptions<AiOptions> options, ILogger<OllamaAiService> logger) : IAiService
{
    public const string EngineName = "Ollama";

    public async Task<AiEngineStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var opts = options.Value;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(opts.StatusTimeoutSeconds));

        try
        {
            var version = await httpClient.GetFromJsonAsync<VersionResponse>("api/version", timeout.Token);
            var tags = await httpClient.GetFromJsonAsync<TagsResponse>("api/tags", timeout.Token);
            var installed = tags?.Models?.Select(m => m.Name).Where(n => !string.IsNullOrEmpty(n)).Cast<string>().ToList() ?? [];

            var hasModel = installed.Any(m => ModelNamesMatch(m, opts.Model));
            return new AiEngineStatus(
                hasModel ? AiEngineState.Ready : AiEngineState.ModelMissing,
                EngineName, opts.Endpoint, opts.Model, version?.Version, installed,
                hasModel ? null : $"Silnik działa, ale model „{opts.Model}” nie jest zainstalowany.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or NotSupportedException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            logger.LogDebug(ex, "AI engine at {Endpoint} is not available", opts.Endpoint);
            return new AiEngineStatus(AiEngineState.Unavailable, EngineName, opts.Endpoint, opts.Model, null, [],
                "Lokalny silnik AI nie odpowiada.");
        }
    }

    public async IAsyncEnumerable<AiChatChunk> ChatAsync(IReadOnlyList<AiChatMessage> messages, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var opts = options.Value;
        var body = new Dictionary<string, object?>
        {
            ["model"] = opts.Model,
            ["messages"] = messages.Select(m => new { role = m.Role, content = m.Content }).ToList(),
            ["stream"] = true,
            ["think"] = false,
            ["keep_alive"] = opts.KeepAlive,
            ["options"] = new Dictionary<string, object?>
            {
                ["temperature"] = opts.Temperature,
                ["num_ctx"] = opts.ContextTokens,
                ["num_thread"] = opts.EffectiveThreads,
                ["num_predict"] = opts.MaxAnswerTokens,
                ["num_gpu"] = opts.ForceCpu ? 0 : null
            }.Where(kv => kv.Value is not null).ToDictionary()
        };

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(opts.RequestTimeoutSeconds));
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/chat") { Content = JsonContent.Create(body) };
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(timeout.Token);
            throw new HttpRequestException($"Silnik AI zwrócił {(int)response.StatusCode}: {Truncate(error, 300)}");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var reader = new StreamReader(stream);
        while (await reader.ReadLineAsync(timeout.Token) is { } line)
        {
            if (line.Length == 0) continue;
            var chunk = ParseChunk(line);
            if (chunk is null) continue;
            yield return chunk;
            if (chunk.Done) yield break;
        }
    }

    /// <summary>One NDJSON line of /api/chat: {"message":{"content":"…"},"done":false} … {"done":true,"eval_count":…}.</summary>
    internal static AiChatChunk? ParseChunk(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out var err)) throw new HttpRequestException($"Silnik AI: {err.GetString()}");
        var text = root.TryGetProperty("message", out var msg) && msg.TryGetProperty("content", out var c) ? c.GetString() ?? "" : "";
        var done = root.TryGetProperty("done", out var d) && d.ValueKind == JsonValueKind.True;
        if (!done) return new AiChatChunk(text);

        int? Int(string name) => root.TryGetProperty(name, out var v) && v.TryGetInt32(out var i) ? i : null;
        var evalCount = Int("eval_count");
        double? speed = evalCount is { } n && root.TryGetProperty("eval_duration", out var dur) && dur.TryGetInt64(out var ns) && ns > 0 ? n / (ns / 1e9) : null;
        var truncated = root.TryGetProperty("done_reason", out var reason) && reason.GetString() == "length";
        return new AiChatChunk(text, true, Int("prompt_eval_count"), evalCount, speed, truncated);
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    /// <summary>Ollama treats a model name without a tag as ":latest".</summary>
    public static bool ModelNamesMatch(string installed, string configured)
    {
        static string Normalize(string name) => name.Contains(':') ? name : name + ":latest";
        return string.Equals(Normalize(installed.Trim()), Normalize(configured.Trim()), StringComparison.OrdinalIgnoreCase);
    }

    private sealed record VersionResponse([property: JsonPropertyName("version")] string? Version);

    private sealed record TagsResponse([property: JsonPropertyName("models")] List<TagModel>? Models);

    private sealed record TagModel([property: JsonPropertyName("name")] string? Name);
}
