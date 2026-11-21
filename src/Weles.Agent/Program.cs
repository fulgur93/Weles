using Weles.Agent.Communication;
using Weles.Agent.Configuration;
using Weles.Agent.Scanning;
using Weles.Agent.Workers;
using Weles.Infrastructure.Agents;
using Weles.Infrastructure.Discovery;
using Weles.Infrastructure.Scanning;

// weles-agent enroll --server https://192.168.0.10:7443 --pin <sha256> --code <code> [--config <file>]
// weles-agent run [--config <file>]      (default; also how the system service starts it)
// weles-agent status [--config <file>]
var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0] : "run";
var options = Options(args.Skip(command == "run" && (args.Length == 0 || args[0].StartsWith('-')) ? 0 : 1).ToArray());
var configFile = options.GetValueOrDefault("config") ?? AgentConfigStore.DefaultPath();

switch (command)
{
    case "enroll":
        return await EnrollAsync(options, configFile);
    case "status":
        return Status(configFile);
    case "run":
        break;
    default:
        Console.Error.WriteLine($"Nieznane polecenie „{command}”. Użycie: weles-agent [run|enroll|status] …");
        return 2;
}

var builder = Host.CreateApplicationBuilder(args.Where(a => a != "run").ToArray());
builder.Services.AddWindowsService(o => o.ServiceName = "WELES Agent");
builder.Services.AddSystemd();
builder.Services.Configure<ScanOptions>(builder.Configuration.GetSection(ScanOptions.SectionName));
builder.Services.AddSingleton(new AgentPaths(configFile));
builder.Services.AddSingleton<OuiDatabase>();
builder.Services.AddSingleton<LocalNetworkDiscovery>();
builder.Services.AddHostedService<AgentWorker>();
await builder.Build().RunAsync();
return 0;

static async Task<int> EnrollAsync(IReadOnlyDictionary<string, string> options, string configFile)
{
    if (!options.TryGetValue("server", out var server) || !options.TryGetValue("pin", out var pin) || !options.TryGetValue("code", out var code))
    {
        Console.Error.WriteLine("Użycie: weles-agent enroll --server https://ADRES:PORT --pin ODCISK_SHA256 --code KOD [--config PLIK]");
        return 2;
    }

    try
    {
        using var client = new CentralClient(server, pin);
        var network = new LocalNetworkDiscovery(new OuiDatabase());
        var response = await client.EnrollAsync(new EnrollRequest(code, SystemInfoCollector.Collect(network)), CancellationToken.None);
        AgentConfigStore.Save(configFile, new AgentConfig(server.TrimEnd('/'), AgentProtocol.NormalizePin(pin), response.AgentId, response.Name, response.Token));
        Console.WriteLine($"Zarejestrowano agenta „{response.Name}” (#{response.AgentId}). Konfiguracja: {configFile}");
        Console.WriteLine("Uruchom usługę agenta (systemd: systemctl enable --now weles-agent; Windows: Start-Service \"WELES Agent\").");
        return 0;
    }
    catch (CentralException ex)
    {
        Console.Error.WriteLine($"WELES odrzucił rejestrację: {ex.Message}");
        return 1;
    }
    catch (HttpRequestException ex)
    {
        Console.Error.WriteLine($"Nie można połączyć się z WELES ({ex.Message}). Sprawdź adres, port, zaporę oraz odcisk certyfikatu (--pin) – połączenie z innym certyfikatem jest zawsze odrzucane.");
        return 1;
    }
    catch (ArgumentException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 2;
    }
}

static int Status(string configFile)
{
    var config = AgentConfigStore.Load(configFile);
    if (config is null)
    {
        Console.WriteLine($"Agent nie jest zarejestrowany (brak {configFile}).");
        return 1;
    }

    Console.WriteLine($"Agent „{config.Name}” (#{config.AgentId}), serwer {config.Server}, odcisk certyfikatu {config.Pin[..16]}…, wersja {SystemInfoCollector.Version}");
    return 0;
}

static Dictionary<string, string> Options(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i].StartsWith("--", StringComparison.Ordinal)) result[args[i][2..]] = args[++i];
    }

    return result;
}
