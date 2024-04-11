using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.FluentUI.AspNetCore.Components;
using Microsoft.FluentUI.AspNetCore.Components.DesignTokens;
using PersonalSite;

public class Program
{

    public static async Task Main(string[] args)
    {
        var builder = WebAssemblyHostBuilder.CreateDefault(args);
        builder.RootComponents.Add<App>("#app");
        builder.RootComponents.Add<HeadOutlet>("head::after");
        ConfigureServices(builder.Services, builder.HostEnvironment.BaseAddress);

        await builder.Build().RunAsync();
    }

    static void ConfigureServices(IServiceCollection services, string baseAddress)
    {
        services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(baseAddress) });
        services.AddFluentUIComponents();
        services.AddDesignTokens();
        services.AddDataGridEntityFrameworkAdapter();
    }
}




