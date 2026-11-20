namespace Weles.Core.Entities;

/// <summary>A conversation with the local AI Security Analyst – stored only in the local database.</summary>
public class AiConversation
{
    public int Id { get; set; }
    public required string Title { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    /// <summary>"pl" or "en" – the language the analyst answers in.</summary>
    public string Language { get; set; } = "pl";
    public string? Model { get; set; }

    public List<AiMessage> Messages { get; set; } = [];
}

public class AiMessage
{
    public int Id { get; set; }
    public int ConversationId { get; set; }
    public AiConversation? Conversation { get; set; }

    /// <summary>"user" or "assistant".</summary>
    public required string Role { get; set; }
    public required string Content { get; set; }
    public DateTime CreatedAt { get; set; }

    /// <summary>Which WELES data the answer was given (one label per line) – shown to the user for transparency.</summary>
    public string? ContextSources { get; set; }
    public int? PromptTokens { get; set; }
    public int? AnswerTokens { get; set; }
    public double? TokensPerSecond { get; set; }
    public int? DurationMs { get; set; }

    /// <summary>Set when generation failed or was stopped; the partial answer is kept.</summary>
    public string? Error { get; set; }
}
