namespace Weles.Core.Models;

/// <summary>One message sent to the model. Role: "system", "user" or "assistant".</summary>
public sealed record AiChatMessage(string Role, string Content);

/// <summary>A piece of the streamed answer; the last one has <see cref="Done"/> and the generation statistics.</summary>
/// <param name="Truncated">The answer hit the length limit.</param>
public sealed record AiChatChunk(string Text, bool Done = false, int? PromptTokens = null, int? AnswerTokens = null, double? TokensPerSecond = null, bool Truncated = false);
