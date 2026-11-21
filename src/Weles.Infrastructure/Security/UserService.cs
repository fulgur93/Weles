using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Weles.Core.Entities;
using Weles.Infrastructure.Database;

namespace Weles.Infrastructure.Security;

public sealed record UserView(int Id, string UserName, UserRole Role, bool Disabled, DateTime CreatedAt, DateTime? LastLoginAt, bool Locked);

/// <param name="User">The signed-in user, or null with the reason in <see cref="Error"/>.</param>
public sealed record LoginResult(UserView? User, string? SecurityStamp, string? Error);

/// <summary>
/// Users and roles (RBAC). Passwords: PBKDF2-HMAC-SHA256, 600 000 iterations, 16-byte salt, compared in constant time.
/// After 5 failed logins the account is locked for 5 minutes. The last active administrator cannot be removed, disabled
/// or demoted, so the panel can never be locked out.
/// </summary>
public sealed partial class UserService(IDbContextFactory<WelesDbContext> contextFactory, TimeProvider time, ILogger<UserService> logger)
{
    public const int MinPasswordLength = 10;
    public const int MaxFailedLogins = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(5);
    private const int Iterations = 600_000;

    public async Task<bool> AnyAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await db.Users.AnyAsync(ct);
    }

    public async Task<IReadOnlyList<UserView>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return (await db.Users.AsNoTracking().OrderBy(u => u.UserName).ToListAsync(ct)).Select(View).ToList();
    }

    /// <summary>Creates a user. The very first user must be an administrator.</summary>
    public async Task<(UserView? User, IReadOnlyList<string> Errors)> CreateAsync(string userName, string password, UserRole role, string? by, CancellationToken ct = default)
    {
        userName = userName.Trim();
        var errors = Validate(userName, password);
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        if (!await db.Users.AnyAsync(ct) && role != UserRole.Admin) errors.Add("Pierwsze konto musi mieć rolę Administracja.");
        if (await db.Users.AnyAsync(u => u.UserName == userName, ct)) errors.Add("Użytkownik o tej nazwie już istnieje.");
        if (!Enum.IsDefined(role)) errors.Add("Nieznana rola.");
        if (errors.Count > 0) return (null, errors);

        var user = new AppUser { UserName = userName, PasswordHash = Hash(password), Role = role, SecurityStamp = NewStamp(), CreatedAt = time.GetUtcNow().UtcDateTime };
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("User {User} created with role {Role} by {By}", userName, role, by ?? "setup");
        return (View(user), []);
    }

    public async Task<LoginResult> LoginAsync(string userName, string password, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var user = await db.Users.SingleOrDefaultAsync(u => u.UserName == userName.Trim(), ct);
        const string generic = "Nieprawidłowa nazwa użytkownika lub hasło.";
        if (user is null)
        {
            Verify(password, DummyHash); // same work as for an existing user – no timing hint which names exist
            logger.LogWarning("Failed login for unknown user");
            return new LoginResult(null, null, generic);
        }

        if (user.LockedUntil > now) return new LoginResult(null, null, $"Konto jest zablokowane do {user.LockedUntil.Value.ToLocalTime():HH:mm} po zbyt wielu nieudanych próbach.");
        if (!Verify(password, user.PasswordHash))
        {
            user.FailedLogins++;
            if (user.FailedLogins >= MaxFailedLogins)
            {
                user.LockedUntil = now + LockoutDuration;
                user.FailedLogins = 0;
                logger.LogWarning("User {User} locked after {Count} failed logins", user.UserName, MaxFailedLogins);
            }

            await db.SaveChangesAsync(ct);
            return new LoginResult(null, null, generic);
        }

        if (user.Disabled) return new LoginResult(null, null, "Konto jest wyłączone.");
        user.FailedLogins = 0;
        user.LockedUntil = null;
        user.LastLoginAt = now;
        await db.SaveChangesAsync(ct);
        logger.LogInformation("User {User} signed in ({Role})", user.UserName, user.Role);
        return new LoginResult(View(user), user.SecurityStamp, null);
    }

    /// <summary>The session is valid while the user exists, is enabled and the stamp has not changed.</summary>
    public async Task<bool> IsSessionValidAsync(int userId, string? stamp, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().AnyAsync(u => u.Id == userId && !u.Disabled && u.SecurityStamp == stamp, ct);
    }

    public async Task<IReadOnlyList<string>> SetRoleAsync(int id, UserRole role, string? by, CancellationToken ct = default) =>
        await ChangeAsync(id, by, (user, admins) =>
        {
            if (user.Role == UserRole.Admin && role != UserRole.Admin && admins <= 1) return "Nie można odebrać roli ostatniemu administratorowi.";
            user.Role = role;
            return null;
        }, $"role {role}", ct);

    public async Task<IReadOnlyList<string>> SetDisabledAsync(int id, bool disabled, string? by, CancellationToken ct = default) =>
        await ChangeAsync(id, by, (user, admins) =>
        {
            if (disabled && user.Role == UserRole.Admin && admins <= 1) return "Nie można wyłączyć ostatniego administratora.";
            user.Disabled = disabled;
            return null;
        }, disabled ? "disabled" : "enabled", ct);

    public async Task<IReadOnlyList<string>> ResetPasswordAsync(int id, string password, string? by, CancellationToken ct = default)
    {
        if (Validate("ok", password) is { Count: > 0 } errors) return errors;
        return await ChangeAsync(id, by, (user, _) =>
        {
            user.PasswordHash = Hash(password);
            user.LockedUntil = null;
            user.FailedLogins = 0;
            return null;
        }, "password reset", ct);
    }

    public async Task<IReadOnlyList<string>> DeleteAsync(int id, string? by, CancellationToken ct = default)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return ["Użytkownik nie istnieje."];
        if (user.Role == UserRole.Admin && await ActiveAdminsAsync(db, ct) <= 1) return ["Nie można usunąć ostatniego administratora."];
        db.Users.Remove(user);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("User {User} deleted by {By}", user.UserName, by ?? "-");
        return [];
    }

    private async Task<IReadOnlyList<string>> ChangeAsync(int id, string? by, Func<AppUser, int, string?> change, string what, CancellationToken ct)
    {
        await using var db = await contextFactory.CreateDbContextAsync(ct);
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return ["Użytkownik nie istnieje."];
        if (change(user, await ActiveAdminsAsync(db, ct)) is { } error) return [error];
        user.SecurityStamp = NewStamp(); // existing sessions of this user end
        await db.SaveChangesAsync(ct);
        logger.LogInformation("User {User}: {What} by {By}", user.UserName, what, by ?? "-");
        return [];
    }

    private static Task<int> ActiveAdminsAsync(WelesDbContext db, CancellationToken ct) => db.Users.CountAsync(u => u.Role == UserRole.Admin && !u.Disabled, ct);

    private static List<string> Validate(string userName, string password)
    {
        var errors = new List<string>();
        if (!UserNamePattern().IsMatch(userName)) errors.Add("Nazwa użytkownika: 3–50 znaków – litery, cyfry, „.”, „-”, „_”, „@”.");
        if (password.Length < MinPasswordLength) errors.Add($"Hasło musi mieć co najmniej {MinPasswordLength} znaków.");
        if (password.Length > 200) errors.Add("Hasło jest za długie.");
        return errors;
    }

    internal static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    internal static bool Verify(string password, string stored)
    {
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], out var iterations)) return false;
        var expected = Convert.FromBase64String(parts[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(parts[2]), iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static readonly string DummyHash = Hash(Guid.NewGuid().ToString());

    private static string NewStamp() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    private UserView View(AppUser u) => new(u.Id, u.UserName, u.Role, u.Disabled, u.CreatedAt, u.LastLoginAt, u.LockedUntil > time.GetUtcNow().UtcDateTime);

    [GeneratedRegex(@"^[\p{L}0-9._@-]{3,50}$")]
    private static partial Regex UserNamePattern();
}
