using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Weles.Core.Models;
using Weles.Infrastructure.AI;

namespace Weles.Tests.Infrastructure;

public class OllamaAiServiceTests
{
    private static OllamaAiService Create(Func<HttpRequestMessage, HttpResponseMessage> responder, string model = "qwen3:4b-instruct-2507-q4_K_M")
    {
        var client = new HttpClient(new StubHandler(responder)) { BaseAddress = new Uri("http://127.0.0.1:11435/") };
        return new OllamaAiService(client, Options.Create(new AiOptions { Model = model }), NullLogger<OllamaAiService>.Instance);
    }

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    [Fact]
    public async Task Ready_when_engine_responds_and_model_is_installed()
    {
        var service = Create(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/version" => Json("""{"version":"0.13.0"}"""),
            "/api/tags" => Json("""{"models":[{"name":"qwen3:4b-instruct-2507-q4_K_M","size":2500000000}]}"""),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        });

        var status = await service.GetStatusAsync();

        Assert.Equal(AiEngineState.Ready, status.State);
        Assert.Equal("0.13.0", status.EngineVersion);
        Assert.Single(status.InstalledModels);
    }

    [Fact]
    public async Task ModelMissing_when_engine_responds_without_configured_model()
    {
        var service = Create(req => req.RequestUri!.AbsolutePath == "/api/version"
            ? Json("""{"version":"0.13.0"}""")
            : Json("""{"models":[{"name":"llama3:8b"}]}"""));

        var status = await service.GetStatusAsync();

        Assert.Equal(AiEngineState.ModelMissing, status.State);
        Assert.NotNull(status.Message);
    }

    [Fact]
    public async Task Unavailable_when_engine_does_not_respond()
    {
        var service = Create(_ => throw new HttpRequestException("connection refused"));

        var status = await service.GetStatusAsync();

        Assert.Equal(AiEngineState.Unavailable, status.State);
        Assert.False(status.IsReady);
    }

    [Fact]
    public async Task Unavailable_when_engine_returns_garbage()
    {
        var service = Create(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>not ollama</html>") });

        Assert.Equal(AiEngineState.Unavailable, (await service.GetStatusAsync()).State);
    }

    [Theory]
    [InlineData("qwen3:4b", "qwen3:4b", true)]
    [InlineData("bielik:latest", "bielik", true)]
    [InlineData("Qwen3:4B", "qwen3:4b", true)]
    [InlineData("qwen3:8b", "qwen3:4b", false)]
    public void Model_name_matching_follows_ollama_tag_rules(string installed, string configured, bool expected)
    {
        Assert.Equal(expected, OllamaAiService.ModelNamesMatch(installed, configured));
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}
