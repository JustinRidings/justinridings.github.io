using Microsoft.JSInterop;

namespace PersonalSite.Services;

/// <summary>
/// Plays UI sound effects via the Web Audio API. Tones are synthesized so we don't
/// need to ship copyrighted XP sound files. Drop-in WAVs at /sounds/ would be picked
/// up trivially if you ever want them.
/// </summary>
public sealed class SoundService
{
    private readonly IJSRuntime _js;
    private bool _enabled = true;

    public SoundService(IJSRuntime js) => _js = js;

    public bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    public Task StartupAsync() => PlayChordAsync(new[] { 523.25, 659.25, 783.99 }, 0.55, 0.18);
    public Task ErrorAsync()   => PlayChordAsync(new[] { 196.0, 233.08 }, 0.35, 0.22);
    public Task ClickAsync()   => PlayChordAsync(new[] { 880.0 }, 0.04, 0.10);
    public Task MinimizeAsync()=> PlayChordAsync(new[] { 660.0, 440.0 }, 0.10, 0.08);

    private async Task PlayChordAsync(double[] freqs, double duration, double volume)
    {
        if (!_enabled) return;
        try
        {
            await _js.InvokeVoidAsync("xpSound.play", freqs, duration, volume);
        }
        catch { /* ignore — sound is non-essential */ }
    }
}
