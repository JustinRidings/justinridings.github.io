using Microsoft.JSInterop;

namespace PersonalSite.Services;

/// <summary>
/// Tracks whether the boot/login sequence has already played in this browser session.
/// </summary>
public sealed class BootService
{
    private const string Key = "xp.has-booted";
    private readonly IJSRuntime _js;

    public BootService(IJSRuntime js) => _js = js;

    public async Task<bool> HasBootedThisSessionAsync()
    {
        try
        {
            var v = await _js.InvokeAsync<string?>("sessionStorage.getItem", Key);
            return v == "1";
        }
        catch
        {
            return false;
        }
    }

    public async Task MarkBootedAsync()
    {
        try { await _js.InvokeVoidAsync("sessionStorage.setItem", Key, "1"); }
        catch { /* ignore */ }
    }
}
