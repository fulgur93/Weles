using Weles.Infrastructure.Settings;

namespace Weles.App.Services;

/// <summary>Per-circuit UI theme. Dark is the default; the choice is persisted in the database.</summary>
public sealed class ThemeState(SettingsService settings)
{
    public const string Dark = "dark";
    public const string Light = "light";

    private bool _loaded;

    public string Theme { get; private set; } = Dark;
    public bool IsDark => Theme == Dark;

    public event Action? Changed;

    public async Task EnsureLoadedAsync()
    {
        if (_loaded)
        {
            return;
        }

        var stored = await settings.GetAsync(SettingsService.Keys.Theme);
        Theme = stored == Light ? Light : Dark;
        _loaded = true;
    }

    public async Task SetAsync(string theme)
    {
        Theme = theme == Light ? Light : Dark;
        await settings.SetAsync(SettingsService.Keys.Theme, Theme);
        Changed?.Invoke();
    }

    public Task ToggleAsync() => SetAsync(IsDark ? Light : Dark);
}
