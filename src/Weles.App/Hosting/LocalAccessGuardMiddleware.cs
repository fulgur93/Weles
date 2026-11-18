using Microsoft.Extensions.Options;

namespace Weles.App.Hosting;

public sealed class LocalAccessGuardMiddleware(RequestDelegate next, LocalAccessToken token, IOptions<WelesHostOptions> options, ILogger<LocalAccessGuardMiddleware> logger)
{
    public const string AuthPath = "/auth";

    public async Task InvokeAsync(HttpContext context)
    {
        if (!options.Value.RequireAccessToken)
        {
            await next(context);
            return;
        }

        var request = context.Request;

        // DNS rebinding protection independent of AllowedHosts configuration.
        if (!IsLoopbackHost(request.Host.Host))
        {
            logger.LogWarning("Rejected request with non-loopback Host header");
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        // Cross-site requests (CSRF, cross-site WebSocket hijacking) are rejected even before the cookie check.
        if (IsCrossSite(request))
        {
            logger.LogWarning("Rejected cross-site request to {Path} from origin {Origin}", request.Path, request.Headers.Origin.ToString());
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        var cookieName = CookieNameFor(request);

        if (request.Path.Equals(AuthPath, StringComparison.OrdinalIgnoreCase))
        {
            if (token.Matches(request.Query["token"]))
            {
                context.Response.Cookies.Append(cookieName, token.Value, new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.Strict,
                    Secure = false, // plain HTTP on loopback only
                    IsEssential = true,
                    Path = "/"
                });
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Redirect("/");
                return;
            }

            logger.LogWarning("Invalid access token presented to {Path}", AuthPath);
            await WriteUnauthorizedAsync(context);
            return;
        }

        if (token.Matches(request.Cookies[cookieName]))
        {
            await next(context);
            return;
        }

        await WriteUnauthorizedAsync(context);
    }

    /// <summary>Cookies are not isolated by port, so every instance (normal/demo) uses its own cookie name.</summary>
    public static string CookieNameFor(HttpRequest request) => $"weles_session_{request.Host.Port ?? 0}";

    public static bool IsLoopbackHost(string host) =>
        host is "127.0.0.1" or "localhost" or "[::1]" or "::1";

    private static bool IsCrossSite(HttpRequest request)
    {
        if (string.Equals(request.Headers["Sec-Fetch-Site"], "cross-site", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var origin = request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin))
        {
            return false;
        }

        return !Uri.TryCreate(origin, UriKind.Absolute, out var originUri)
               || !string.Equals(originUri.Authority, request.Host.Value, StringComparison.OrdinalIgnoreCase);
    }

    private static Task WriteUnauthorizedAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        return context.Response.WriteAsync(UnauthorizedPage);
    }

    private const string UnauthorizedPage = """
        <!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><title>WELES – brak dostępu</title>
        <style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0f15;color:#e6edf3;font-family:system-ui,sans-serif}
        main{max-width:520px;padding:32px;border:1px solid #223042;border-radius:14px;background:#111822}
        h1{font-size:20px;margin:0 0 12px}p{color:#9aa7b6;line-height:1.55}code{color:#8fb3ff}</style></head>
        <body><main><h1>Sesja WELES nie jest autoryzowana</h1>
        <p>Panel WELES jest dostępny wyłącznie dla przeglądarki otwartej przez aplikację.
        Uruchom WELES ponownie – otworzy istniejącą sesję – albo użyj adresu wypisanego w konsoli przy starcie.</p>
        <p>To zabezpieczenie chroni lokalny serwer przed dostępem innych użytkowników i stron internetowych.</p></main></body></html>
        """;
}
