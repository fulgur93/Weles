namespace Weles.Core.Entities;

public class ApplicationSetting
{
    public required string Key { get; set; }
    public string? Value { get; set; }
    public DateTime UpdatedAt { get; set; }
}
