using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Weles.Core.Interfaces;
using Weles.Core.Models;

namespace Weles.Infrastructure.AI;

public enum EngineHostState
{
    /// <summary>No bundled runtime – WELES only talks to the configured endpoint.</summary>
    NotBundled,
    Starting,
    Running,
    /// <summary>Something else already answers on the endpoint (an earlier WELES run or the user's own Ollama on that port).</summary>
    External,
    Failed,
    Disabled
}

/// <summary>
/// Starts the bundled Ollama as a child process bound to 127.0.0.1 only, with the models directory shipped with WELES,
/// no CORS origins and no model pruning; restarts it a few times if it crashes and stops it with the application.
/// The user never installs or configures anything.
/// </summary>
public sealed class OllamaProcessHost(IOptions<AiOptions> options, IAiService ai, ILogger<OllamaProcessHost> logger) : BackgroundService
{
    private const int MaxRestarts = 3;
    private Process? _process;

    public EngineHostState State { get; private set; } = EngineHostState.Starting;
    public string? Message { get; private set; }
    public OllamaRuntime? Runtime { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var opts = options.Value;
        if (!opts.ManageEngine)
        {
            State = EngineHostState.Disabled;
            return;
        }

        Runtime = OllamaRuntime.Locate(opts, AppContext.BaseDirectory);
        if (Runtime is null)
        {
            State = EngineHostState.NotBundled;
            Message = "Brak dołączonego silnika Ollama (runtime/ollama) – WELES korzysta tylko ze skonfigurowanego adresu.";
            logger.LogInformation("No bundled Ollama found; using configured endpoint {Endpoint} only", opts.Endpoint);
            return;
        }

        if ((await ai.GetStatusAsync(stoppingToken)).State != AiEngineState.Unavailable)
        {
            State = EngineHostState.External;
            Message = $"Na {opts.Endpoint} działa już silnik AI – WELES z niego korzysta.";
            logger.LogInformation("An engine already answers on {Endpoint}; not starting the bundled one", opts.Endpoint);
            return;
        }

        for (var attempt = 0; attempt <= MaxRestarts && !stoppingToken.IsCancellationRequested; attempt++)
        {
            State = EngineHostState.Starting;
            if (!Start(Runtime, opts))
            {
                State = EngineHostState.Failed;
                return;
            }

            if (await WaitReadyAsync(stoppingToken))
            {
                State = EngineHostState.Running;
                Message = null;
                logger.LogInformation("Bundled Ollama started (pid {Pid}) on {Endpoint}, models in {Models}", _process!.Id, opts.Endpoint, Runtime.ModelsDirectory);
            }

            try
            {
                await _process!.WaitForExitAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            logger.LogWarning("Bundled Ollama exited with code {Code}", _process.ExitCode);
            State = EngineHostState.Failed;
            Message = $"Silnik AI zakończył działanie (kod {_process.ExitCode}).";
            await Task.Delay(TimeSpan.FromSeconds(2 * (attempt + 1)), stoppingToken).ContinueWith(_ => { }, TaskScheduler.Default);
        }
    }

    /// <summary>Environment of the child process: loopback only, our models, nothing pruned, no browser origins.</summary>
    internal static Dictionary<string, string> Environment(AiOptions opts, OllamaRuntime runtime)
    {
        var uri = new Uri(opts.Endpoint);
        return new Dictionary<string, string>
        {
            ["OLLAMA_HOST"] = $"127.0.0.1:{uri.Port}",
            ["OLLAMA_MODELS"] = runtime.ModelsDirectory,
            ["OLLAMA_NOPRUNE"] = "1",
            // An empty value means Ollama's default list, which allows every page served from 127.0.0.1 – instead allow
            // only an origin no browser page can have, so web pages cannot call the engine directly.
            ["OLLAMA_ORIGINS"] = "http://weles.invalid",
            ["OLLAMA_NUM_PARALLEL"] = "1",
            ["OLLAMA_MAX_LOADED_MODELS"] = "1",
            ["OLLAMA_KEEP_ALIVE"] = opts.KeepAlive,
            ["OLLAMA_NO_CLOUD"] = "1",   // no remote inference or web search – everything stays on this computer
            ["OLLAMA_REMOTES"] = "weles.invalid",
            ["OLLAMA_IGPU_ENABLE"] = opts.UseIntegratedGpu ? "1" : ""
        };
    }

    private bool Start(OllamaRuntime runtime, AiOptions opts)
    {
        try
        {
            var psi = new ProcessStartInfo(runtime.Executable, "serve")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(runtime.Executable)!
            };
            foreach (var (key, value) in Environment(opts, runtime)) psi.Environment[key] = value;
            _process = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null");
            _process.OutputDataReceived += (_, e) => { if (e.Data is { Length: > 0 } line) logger.LogDebug("ollama: {Line}", line); };
            _process.ErrorDataReceived += (_, e) => { if (e.Data is { Length: > 0 } line) logger.LogDebug("ollama: {Line}", line); };
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            return true;
        }
        catch (Exception ex)
        {
            Message = $"Nie udało się uruchomić silnika AI: {ex.Message}";
            logger.LogError(ex, "Could not start bundled Ollama {Executable}", runtime.Executable);
            return false;
        }
    }

    private async Task<bool> WaitReadyAsync(CancellationToken ct)
    {
        for (var i = 0; i < 60 && !ct.IsCancellationRequested; i++)
        {
            if (_process is { HasExited: true }) return false;
            if ((await ai.GetStatusAsync(ct)).State != AiEngineState.Unavailable) return true;
            await Task.Delay(500, ct);
        }

        return false;
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        if (_process is { HasExited: false } p)
        {
            try
            {
                p.Kill(entireProcessTree: true);
                await p.WaitForExitAsync(cancellationToken);
                logger.LogInformation("Bundled Ollama stopped");
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException)
            {
                logger.LogDebug(ex, "Stopping Ollama");
            }
        }
    }

    /// <summary>
    /// Idempotent: the host is registered as a singleton and as a hosted service, so the container disposes it twice –
    /// the second call used to throw on the already disposed process and ended every shutdown with an unhandled exception
    /// (found by the clean-system installation test, Stage 11).
    /// </summary>
    public override void Dispose()
    {
        var process = Interlocked.Exchange(ref _process, null);
        if (process is not null)
        {
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Already gone.
            }

            process.Dispose();
        }

        base.Dispose();
        GC.SuppressFinalize(this);
    }
}
