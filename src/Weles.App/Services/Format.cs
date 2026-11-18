namespace Weles.App.Services;

public static class Format
{
    public static string Bytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024d:0.0} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1024d / 1024d:0.0} MB",
        _ => $"{bytes / 1024d / 1024d / 1024d:0.00} GB"
    };
}
