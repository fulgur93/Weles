using System.Net.Http.Json;
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
