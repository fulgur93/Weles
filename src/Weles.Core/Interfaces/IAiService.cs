using Weles.Core.Models;

namespace Weles.Core.Interfaces;

/// <summary>
/// Local AI engine abstraction. The application never depends on Ollama directly,
/// so the engine can be replaced (e.g. by llama.cpp's llama-server).
/// </summary>
public interface IAiService
{
    /// <summary>Checks the engine and model availability. Never throws for connectivity problems.</summary>
    Task<AiEngineStatus> GetStatusAsync(CancellationToken cancellationToken = default);
}
