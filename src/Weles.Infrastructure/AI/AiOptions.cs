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

    /// <summary>Start the bundled Ollama as a child process (unless something already answers on <see cref="Endpoint"/>).</summary>
    public bool ManageEngine { get; set; } = true;

    /// <summary>Directory with bin/ollama; null = next to the application (package) or artifacts/ai-runtime (development).</summary>
    public string? RuntimeDirectory { get; set; }

    /// <summary>OLLAMA_MODELS directory; null = "models" next to the runtime directory.</summary>
    public string? ModelsDirectory { get; set; }

    /// <summary>Context window in tokens – data from the WELES database plus the conversation must fit.</summary>
    public int ContextTokens { get; set; } = 6144;

    /// <summary>Low temperature: answers must stick to the data, not be creative.</summary>
    public double Temperature { get; set; } = 0.1;

    public string KeepAlive { get; set; } = "30m";

    /// <summary>Upper limit of an answer in tokens – on a CPU 768 tokens take about 1.5 minutes to write.</summary>
    public int MaxAnswerTokens { get; set; } = 768;

    /// <summary>Run on the CPU even if Ollama finds a GPU.</summary>
    public bool ForceCpu { get; set; }

    /// <summary>
    /// CPU threads for inference; 0 = automatic (up to 8). Without it llama.cpp uses only the performance cores – on a
    /// hybrid laptop CPU (Core Ultra 5 125U, 2 P-cores) that halves the speed (measured 4.3 → 8.5 tokens/s).
    /// </summary>
    public int Threads { get; set; }

    /// <summary>
    /// Let Ollama use an integrated GPU (Vulkan). Measured on Intel Graphics (Meteor Lake): reading the prompt 2× faster,
    /// writing the answer slower than 8 CPU threads – overall similar, so off by default.
    /// </summary>
    public bool UseIntegratedGpu { get; set; }

    public int EffectiveThreads => Threads > 0 ? Threads : Math.Clamp(Environment.ProcessorCount - 2, 2, 8);

    public int RequestTimeoutSeconds { get; set; } = 600;
}
