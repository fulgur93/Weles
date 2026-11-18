namespace Weles.Infrastructure.AI;

public sealed class AiOptions
{
    public const string SectionName = "Weles:Ai";

    /// <summary>
    /// Endpoint of the local engine. The bundled Ollama listens on 11435 so it never collides
    /// with an Ollama the user may have installed on the default 11434.
    /// </summary>
    public string Endpoint { get; set; } = "http://127.0.0.1:11435";

    public string Model { get; set; } = "qwen3:4b-instruct-2507-q4_K_M";

    public int StatusTimeoutSeconds { get; set; } = 3;
}
