namespace Weles.Core.Models;

public enum AiEngineState
{
    /// <summary>The engine endpoint did not respond.</summary>
    Unavailable = 0,
    /// <summary>The engine responds but the configured model is not installed.</summary>
    ModelMissing = 1,
    /// <summary>Engine and model are available.</summary>
    Ready = 2
}

public sealed record AiEngineStatus(
    AiEngineState State,
    string EngineName,
    string Endpoint,
    string ConfiguredModel,
    string? EngineVersion,
    IReadOnlyList<string> InstalledModels,
    string? Message)
{
    public bool IsReady => State == AiEngineState.Ready;
}
