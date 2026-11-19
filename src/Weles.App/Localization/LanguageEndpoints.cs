namespace Weles.App.Localization;

public static class LanguageEndpoints
{
    /// <summary>
    /// GET /language/{code}?returnUrl=/path – stores the language and redirects back with a full page load, so the new
    /// Blazor circuit starts in the new culture. A server endpoint instead of NavigationManager.NavigateTo(forceLoad):
    /// the forced reload tore down the circuit before the browser acknowledged it and logged an unhandled exception.
    /// Behind LocalAccessGuard like every other request; only local return paths are accepted.
    /// </summary>
    public static void MapLanguageEndpoints(this IEndpointRouteBuilder app) =>
        app.MapGet("/language/{code}", async (string code, string? returnUrl, LanguageState language) =>
        {
            await language.SetAsync(code);
            return Results.LocalRedirect(SafeReturnUrl(returnUrl));
        });

    /// <summary>Only paths on this server ("/assets?net=all"), never "//host" or absolute URLs.</summary>
    internal static string SafeReturnUrl(string? returnUrl) =>
        returnUrl is { Length: > 0 } url && url[0] == '/' && !url.StartsWith("//", StringComparison.Ordinal) && !url.StartsWith("/\\", StringComparison.Ordinal) && !url.Contains("://", StringComparison.Ordinal)
            ? url
            : "/";
}
