using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.Core.Interfaces;
using Weles.Core.Models;
using Weles.Infrastructure.AI;
using Weles.Tests.Support;

namespace Weles.Tests.AI;

public class OllamaProcessHostTests
{
    /// <summary>Unavailable until the host started the engine, then ready.</summary>
    private sealed class FakeEngine : IAiService
    {
        private int _calls;

        public Task<AiEngineStatus> GetStatusAsync(CancellationToken ct = default) =>
            Task.FromResult(new AiEngineStatus(Interlocked.Increment(ref _calls) == 1 ? AiEngineState.Unavailable : AiEngineState.Ready, "fake", "", "m", null, ["m"], null));

        public async IAsyncEnumerable<AiChatChunk> ChatAsync(IReadOnlyList<AiChatMessage> messages, [EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.Yield();
            yield break;
        }
    }

    /// <summary>
    /// Regression (Stage 11, clean Ubuntu container): the host is disposed twice by the container (singleton + hosted
    /// service) – the second call threw on the disposed process and every shutdown ended with an unhandled exception.
    /// </summary>
    [Fact]
    public async Task Stopping_kills_the_engine_and_disposing_twice_is_safe()
    {
        if (OperatingSystem.IsWindows()) return; // the stand-in engine is a shell script
        var dir = TempDirectory.Create();
        try
        {
            var exe = Path.Combine(dir, "bin", "ollama");
            Directory.CreateDirectory(Path.GetDirectoryName(exe)!);
            var marker = Path.Combine(dir, "pid");
            await File.WriteAllTextAsync(exe, $"#!/bin/sh\necho $$ > '{marker}'\nexec sleep 120\n");
            File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var host = new OllamaProcessHost(Options.Create(new AiOptions { RuntimeDirectory = dir, ModelsDirectory = Path.Combine(dir, "models") }),
                new FakeEngine(), NullLogger<OllamaProcessHost>.Instance);
            await host.StartAsync(CancellationToken.None);
            for (var i = 0; i < 100 && host.State != EngineHostState.Running; i++) await Task.Delay(50);
            Assert.Equal(EngineHostState.Running, host.State);
            for (var i = 0; i < 100 && !File.Exists(marker); i++) await Task.Delay(50);
            var pid = int.Parse((await File.ReadAllTextAsync(marker)).Trim());

            await host.StopAsync(CancellationToken.None);
            host.Dispose();
            host.Dispose();
            Assert.False(Directory.Exists($"/proc/{pid}") && !File.ReadAllText($"/proc/{pid}/stat").Contains(" Z "), "the engine process was not stopped");
        }
        finally
        {
            TempDirectory.Delete(dir);
        }
    }
}
