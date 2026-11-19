using System.Globalization;
using Microsoft.AspNetCore.Localization;
using Weles.Infrastructure.Settings;

namespace Weles.App.Localization;

/// <summary>
/// Application language (Polish by default), stored in settings. Applied to every request through a request culture
/// provider, so a new Blazor circuit – e.g. after switching and reloading the page – runs in the chosen language.
/// </summary>
public sealed class LanguageState(SettingsService settings)
{
    public const string SettingKey = "ui.language";
    public static readonly IReadOnlyList<(string Code, string Name, string Culture)> Languages = [("pl", "Polski", "pl-PL"), ("en", "English", "en-GB")];

    private volatile string _code = "pl";

    public string Code => _code;

    public static CultureInfo CultureOf(string code) => CultureInfo.GetCultureInfo(Languages.FirstOrDefault(l => l.Code == code).Culture ?? "pl-PL");

    public async Task LoadAsync()
    {
        var stored = await settings.GetAsync(SettingKey);
        if (Languages.Any(l => l.Code == stored)) _code = stored!;
    }

    public async Task SetAsync(string code)
    {
        if (Languages.All(l => l.Code != code)) return;
        await settings.SetAsync(SettingKey, code);
        _code = code;
    }

    public sealed class Provider(LanguageState state) : RequestCultureProvider
    {
        public override Task<ProviderCultureResult?> DetermineProviderCultureResult(HttpContext httpContext)
        {
            var culture = CultureOf(state.Code).Name;
            return Task.FromResult<ProviderCultureResult?>(new ProviderCultureResult(culture, culture));
        }
    }
}
