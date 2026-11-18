namespace Weles.App.Hosting;

/// <summary>
/// Translates friendly command line switches into configuration keys:
/// <c>--port 5090</c>, <c>--data-dir PATH</c>, <c>--demo</c>, <c>--no-browser</c>.
/// </summary>
public static class CommandLine
{
    public static string[] Normalize(string[] args)
    {
        var result = new List<string>(args.Length);
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--demo":
                    result.Add("--Weles:DemoMode=true");
                    break;
                case "--no-browser":
                    result.Add("--Weles:OpenBrowser=false");
                    break;
                case "--port" when i + 1 < args.Length:
                    result.Add($"--Weles:Port={args[++i]}");
                    break;
                case "--data-dir" when i + 1 < args.Length:
                    result.Add($"--Weles:DataDirectory={args[++i]}");
                    break;
                default:
                    result.Add(args[i]);
                    break;
            }
        }

        return [.. result];
    }
}
