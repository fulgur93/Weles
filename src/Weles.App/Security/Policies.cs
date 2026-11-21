using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Weles.Core.Entities;
using Weles.Infrastructure.Security;

namespace Weles.App.Security;

/// <summary>
/// RBAC policies. Read – every signed-in user (pages, exports). Modify – Operator and up (edit existing data, run scans).
/// Manage – Editor and up (add and delete: scopes, signatures, imports, reports). Admin – users, settings, agents.
/// </summary>
public static class Policies
{
    public const string Modify = "modify";
    public const string Manage = "manage";
    public const string Admin = "admin";
    public const string StampClaim = "weles:stamp";

    public static void Add(Microsoft.AspNetCore.Authorization.AuthorizationOptions o)
    {
        o.AddPolicy(Admin, p => p.RequireRole(nameof(UserRole.Admin)));
        o.AddPolicy(Manage, p => p.RequireRole(nameof(UserRole.Admin), nameof(UserRole.Editor)));
        o.AddPolicy(Modify, p => p.RequireRole(nameof(UserRole.Admin), nameof(UserRole.Editor), nameof(UserRole.Operator)));
    }

    public static string RoleLabel(UserRole role) => role switch
    {
        UserRole.Admin => Localization.L.T("Administracja"),
        UserRole.Editor => Localization.L.T("Dodawanie, usuwanie, modyfikacja"),
        UserRole.Operator => Localization.L.T("Modyfikacja i odczyt"),
        _ => Localization.L.T("Odczyt")
    };

    public static ClaimsPrincipal Principal(UserView user, string stamp) => new(new ClaimsIdentity(
    [
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.Role, user.Role.ToString()),
        new Claim(StampClaim, stamp)
    ], CookieAuthenticationDefaults.AuthenticationScheme));

    /// <summary>Every request re-checks the user: removed, disabled or changed (role, password) → the session ends.</summary>
    public static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var users = context.HttpContext.RequestServices.GetRequiredService<UserService>();
        var principal = context.Principal;
        if (!int.TryParse(principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var id) || !await users.IsSessionValidAsync(id, principal.FindFirstValue(StampClaim)))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}

public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        // Plain form posts. CSRF: LocalAccessGuardMiddleware rejects cross-site requests and the cookies are SameSite=Strict.
        app.MapPost("/account/login", async (HttpContext http, UserService users) =>
        {
            var form = await http.Request.ReadFormAsync();
            var returnUrl = LocalPath(form["returnUrl"]);
            var result = await users.LoginAsync(form["userName"].ToString(), form["password"].ToString());
            if (result.User is null) return Results.Redirect($"/login?error={Uri.EscapeDataString(result.Error ?? "")}&returnUrl={Uri.EscapeDataString(returnUrl)}");
            await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, Policies.Principal(result.User, result.SecurityStamp!));
            return Results.Redirect(returnUrl);
        }).DisableAntiforgery().AllowAnonymous();

        app.MapPost("/account/setup", async (HttpContext http, UserService users) =>
        {
            if (await users.AnyAsync()) return Results.Redirect("/login");
            var form = await http.Request.ReadFormAsync();
            if (form["password"] != form["password2"]) return Results.Redirect($"/setup?error={Uri.EscapeDataString("Hasła się różnią.")}");
            var (user, errors) = await users.CreateAsync(form["userName"].ToString(), form["password"].ToString(), UserRole.Admin, null);
            if (user is null) return Results.Redirect($"/setup?error={Uri.EscapeDataString(string.Join(" ", errors))}");
            var login = await users.LoginAsync(user.UserName, form["password"].ToString());
            await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, Policies.Principal(login.User!, login.SecurityStamp!));
            return Results.Redirect("/");
        }).DisableAntiforgery().AllowAnonymous();

        app.MapPost("/account/logout", async (HttpContext http) =>
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect("/login");
        }).DisableAntiforgery().AllowAnonymous();
    }

    /// <summary>Only a local path – never an absolute or protocol-relative URL (open redirect).</summary>
    public static string LocalPath(string? url) =>
        url is { Length: > 0 } u && u.StartsWith('/') && !u.StartsWith("//") && !u.StartsWith("/\\") && !u.Contains("://") ? u : "/";
}

/// <summary>Role checks in component code (for state that decides what is rendered).</summary>
public static class Access
{
    public static async Task<bool> CanAsync(Task<Microsoft.AspNetCore.Components.Authorization.AuthenticationState>? state, Microsoft.AspNetCore.Authorization.IAuthorizationService authorization, string policy) =>
        state is not null && (await authorization.AuthorizeAsync((await state).User, null, policy)).Succeeded;
}
