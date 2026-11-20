namespace Weles.Infrastructure.AI;

/// <summary>Where the bundled Ollama and its models are.</summary>
public sealed record OllamaRuntime(string Executable, string ModelsDirectory)
{
    /// <summary>
    /// Package layout: weles/app (WELES), weles/runtime/ollama/bin/ollama, weles/models. Development: artifacts/ai-runtime
    /// (prepared by deploy/tools/fetch-ai-runtime.sh). Null when no runtime is bundled.
    /// </summary>
    public static OllamaRuntime? Locate(AiOptions options, string baseDirectory)
    {
        var executableName = OperatingSystem.IsWindows() ? "ollama.exe" : "ollama";
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(options.RuntimeDirectory)) candidates.Add(options.RuntimeDirectory);
        candidates.Add(Path.Combine(baseDirectory, "..", "runtime", "ollama"));
        candidates.Add(Path.Combine(baseDirectory, "runtime", "ollama"));
        for (var dir = new DirectoryInfo(baseDirectory); dir is not null; dir = dir.Parent)
        {
            candidates.Add(Path.Combine(dir.FullName, "artifacts", "ai-runtime", "ollama"));
        }

        foreach (var candidate in candidates)
        {
            foreach (var exe in (string[])[Path.Combine(candidate, "bin", executableName), Path.Combine(candidate, executableName)])
            {
                if (!File.Exists(exe)) continue;
                var root = Path.GetFullPath(candidate);
                var models = options.ModelsDirectory is { Length: > 0 } configured
                    ? configured
                    : Path.Combine(Directory.GetParent(root)!.FullName, "models");
                return new OllamaRuntime(Path.GetFullPath(exe), Path.GetFullPath(models));
            }
        }

        return null;
    }
}
