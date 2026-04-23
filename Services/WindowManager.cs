using PersonalSite.Components.Desktop;

namespace PersonalSite.Services;

/// <summary>
/// Static metadata describing an "app" that can be opened on the XP desktop.
/// </summary>
public sealed record AppDefinition(
    string Key,
    string Title,
    string IconHtml,
    Type ComponentType,
    int DefaultWidth = 640,
    int DefaultHeight = 460,
    bool SingleInstance = true);

/// <summary>
/// Runtime state of an open window.
/// </summary>
public sealed class WindowState
{
    public required string Id { get; init; }
    public required AppDefinition App { get; init; }

    public double X { get; set; }
    public double Y { get; set; }
    public double Width { get; set; }
    public double Height { get; set; }

    public int ZIndex { get; set; }

    public bool IsMinimized { get; set; }
    public bool IsMaximized { get; set; }

    // Stash for restore from maximized
    public double RestoreX, RestoreY, RestoreWidth, RestoreHeight;

    public Dictionary<string, object?>? Parameters { get; set; }
}

/// <summary>
/// Tracks open windows and registered apps for the XP desktop.
/// </summary>
public sealed class WindowManager
{
    private readonly List<WindowState> _windows = new();
    private readonly Dictionary<string, AppDefinition> _registry = new(StringComparer.OrdinalIgnoreCase);
    private int _zCounter = 10;
    private int _spawnOffset;

    public IReadOnlyList<WindowState> Windows => _windows;
    public IReadOnlyDictionary<string, AppDefinition> Registry => _registry;
    public string? FocusedId { get; private set; }

    public event Action? Changed;

    public void Register(AppDefinition app) => _registry[app.Key] = app;

    public WindowState Open(string appKey, Dictionary<string, object?>? parameters = null)
    {
        if (!_registry.TryGetValue(appKey, out var app))
            throw new InvalidOperationException($"Unknown app: {appKey}");

        if (app.SingleInstance)
        {
            var existing = _windows.FirstOrDefault(w => w.App.Key == appKey);
            if (existing is not null)
            {
                existing.IsMinimized = false;
                Focus(existing.Id);
                return existing;
            }
        }

        var spawn = (_spawnOffset++ % 8) * 24;
        var win = new WindowState
        {
            Id = Guid.NewGuid().ToString("N"),
            App = app,
            X = 80 + spawn,
            Y = 60 + spawn,
            Width = app.DefaultWidth,
            Height = app.DefaultHeight,
            ZIndex = ++_zCounter,
            Parameters = parameters,
        };
        _windows.Add(win);
        FocusedId = win.Id;
        Changed?.Invoke();
        return win;
    }

    public void Close(string id)
    {
        var w = _windows.FirstOrDefault(w => w.Id == id);
        if (w is null) return;
        _windows.Remove(w);
        if (FocusedId == id)
            FocusedId = _windows.OrderByDescending(w => w.ZIndex).FirstOrDefault()?.Id;
        Changed?.Invoke();
    }

    public void CloseAll()
    {
        _windows.Clear();
        FocusedId = null;
        Changed?.Invoke();
    }

    public void Focus(string id)
    {
        var w = _windows.FirstOrDefault(w => w.Id == id);
        if (w is null) return;
        w.ZIndex = ++_zCounter;
        w.IsMinimized = false;
        FocusedId = id;
        Changed?.Invoke();
    }

    public void Minimize(string id)
    {
        var w = _windows.FirstOrDefault(w => w.Id == id);
        if (w is null) return;
        w.IsMinimized = true;
        if (FocusedId == id)
            FocusedId = _windows.Where(w => !w.IsMinimized)
                                .OrderByDescending(w => w.ZIndex).FirstOrDefault()?.Id;
        Changed?.Invoke();
    }

    public void ToggleMaximize(string id)
    {
        var w = _windows.FirstOrDefault(w => w.Id == id);
        if (w is null) return;
        if (w.IsMaximized)
        {
            w.IsMaximized = false;
            w.X = w.RestoreX;
            w.Y = w.RestoreY;
            w.Width = w.RestoreWidth;
            w.Height = w.RestoreHeight;
        }
        else
        {
            w.RestoreX = w.X;
            w.RestoreY = w.Y;
            w.RestoreWidth = w.Width;
            w.RestoreHeight = w.Height;
            w.IsMaximized = true;
        }
        Focus(id);
    }

    public void RestoreOrMinimize(string id)
    {
        var w = _windows.FirstOrDefault(w => w.Id == id);
        if (w is null) return;
        if (w.IsMinimized)
        {
            w.IsMinimized = false;
            Focus(id);
        }
        else if (FocusedId == id)
        {
            Minimize(id);
        }
        else
        {
            Focus(id);
        }
    }

    public void Move(string id, double x, double y)
    {
        var w = _windows.FirstOrDefault(w => w.Id == id);
        if (w is null || w.IsMaximized) return;
        w.X = x;
        w.Y = y;
        Changed?.Invoke();
    }

    public void Resize(string id, double width, double height)
    {
        var w = _windows.FirstOrDefault(w => w.Id == id);
        if (w is null || w.IsMaximized) return;
        w.Width = Math.Max(220, width);
        w.Height = Math.Max(140, height);
        Changed?.Invoke();
    }

    public void NotifyChanged() => Changed?.Invoke();
}
