
using System.Net;
using HerdWatch.Models;
using HerdWatch.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// Check for Admin privileges
if (!IsAdministrator())
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("ERROR: HerdWatch requires Administrator privileges to capture ETW events.");
    Console.WriteLine("Please run this application as Administrator.");
    Console.ResetColor();
    Console.WriteLine("\nPress any key to exit...");
    Console.ReadKey();
    return;
}

var builder = Host.CreateApplicationBuilder(args);

// Parse command line arguments
var config = new HerdWatchConfig();
ParseCommandLine(args, config);

builder.Services.AddSingleton(config);
builder.Services.AddSingleton<DnsDataService>();
builder.Services.AddHostedService<EtwMonitorService>();

// Add CORS for development
builder.Services.AddCors(options =>
{
    options.AddPolicy("DevCors", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var host = builder.Build();

if (config.EnableWebUI)
{
    // Run web UI in background
    _ = Task.Run(() => RunWebUI(config, host.Services));
}

await host.RunAsync();

void ParseCommandLine(string[] args, HerdWatchConfig cfg)
{
    for (int i = 0; i < args.Length; i++)
    {
        switch (args[i].ToLower())
        {
            case "--db":
            case "-d":
                if (i + 1 < args.Length) cfg.DbPath = args[++i];
                break;
            case "--port":
            case "-p":
                if (i + 1 < args.Length && int.TryParse(args[++i], out var port))
                    cfg.WebPort = port;
                break;
            case "--web":
            case "-w":
                cfg.EnableWebUI = true;
                break;
            case "--retention":
            case "-r":
                if (i + 1 < args.Length && int.TryParse(args[++i], out var days))
                    cfg.RetentionDays = days;
                break;
            case "--help":
            case "-h":
            case "/?":
                ShowHelp();
                Environment.Exit(0);
                break;
        }
    }

    // Set defaults
    if (string.IsNullOrEmpty(cfg.DbPath))
        cfg.DbPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                 "HerdWatch", "dns.db");
}

void ShowHelp()
{
    Console.WriteLine(@"
HerdWatch - DNS Activity Monitor with Web UI
=============================================

Monitors DNS activity via ETW and provides a web interface to view per-process statistics.

Usage:
  herdwatch [options]

Options:
  -d, --db <path>      SQLite database path (default: %LOCALAPPDATA%\HerdWatch\dns.db)
  -w, --web            Enable web UI
  -p, --port <port>    Web UI port (default: 5000)
  -r, --retention <days>  Retention period in days (default: 7)
  -h, --help          Show this help message

Examples:
  herdwatch --web --port 8080
  herdwatch -d C:\dns.db -w -p 5000
  herdwatch --db .

Web UI:
  http://localhost:5000/ (or specified port)
");
}

async Task RunWebUI(HerdWatchConfig cfg, IServiceProvider services)
{
    var webBuilder = WebApplication.CreateBuilder();
    
    // INFO: We are running two separate hosts (Generic Host for ETW, WebApplication for API).
    // To share the stateful DnsDataService, we resolve it from the main host and register the INSTANCE
    // into the web host. This ensures both parts of the app use the same data service.
    var sharedDnsService = services.GetRequiredService<DnsDataService>();
    webBuilder.Services.AddSingleton(sharedDnsService);
    webBuilder.Services.AddSingleton<SystemActionService>();

    webBuilder.Logging.ClearProviders();
    webBuilder.Logging.AddConsole();

    webBuilder.Services.AddCors();
    
    var app = webBuilder.Build();

    app.UseCors("DevCors");

    // API Endpoints - Now using Dependency Injection properly

    app.MapGet("/api/processes", async (DnsDataService dataService) =>
    {
        var processes = await dataService.GetProcessStats();
        return Results.Json(processes);
    });

    app.MapGet("/api/process/{pid}", async (int pid, DnsDataService dataService) =>
    {
        var stats = await dataService.GetProcessDetails(pid);
        return Results.Json(stats);
    });

    app.MapGet("/api/process/{pid}/live", async (int pid, int? minutes, DnsDataService dataService) =>
    {
        var liveData = await dataService.GetLiveProcessData(pid, minutes ?? 10);
        return Results.Json(liveData);
    });

    app.MapGet("/api/domains", async (int? pid, string? type, string? search, int? minutes, DnsDataService dataService) =>
    {
        var filter = new DomainFilter 
        { 
            ProcessId = pid, 
            QueryType = type, 
            Search = search
        };

        if (minutes.HasValue && minutes.Value > 0)
        {
            filter.StartDate = DateTime.Now.AddMinutes(-minutes.Value);
        }

        var stats = await dataService.GetDomainStats(filter);
        return Results.Json(stats);
    });

    app.MapGet("/api/types", async (DnsDataService dataService) =>
    {
        var types = await dataService.GetQueryTypes();
        return Results.Json(types);
    });

    app.MapGet("/api/events", async (int? page, int? limit, int? pid, string? search, string? type, string? status, string? direction, string? start, string? end, DnsDataService dataService) =>
    {
        var filter = new DnsEventFilter
        {
            Page = page ?? 1,
            PageSize = limit ?? 50,
            ProcessId = pid,
            Search = search,
            QueryType = type,
            Status = status,
            Direction = direction,
            StartDate = start,
            EndDate = end
        };
        var result = await dataService.GetDnsEvents(filter);
        return Results.Json(result);
    });

    app.MapPost("/api/clear", async (DnsDataService dataService) =>
    {
        await dataService.ClearAllData();
        return Results.Ok();
    });

    app.MapGet("/api/beacons", async (DnsDataService dataService) =>
    {
        var candidates = await dataService.GetBeaconCandidates();
        return Results.Json(candidates);
    });

    app.MapPost("/api/sinkhole", async (SinkholeRequest req, SystemActionService actionService) =>
    {
        if (string.IsNullOrEmpty(req.Domain)) return Results.BadRequest("Domain required");
        
        var success = await actionService.SinkholeDomain(req.Domain);
        if (success) 
            return Results.Ok(new { message = $"Domain {req.Domain} sinkholed successfully." });
        else
            return Results.Problem("Failed to sinkhole domain. Ensure you are running as Administrator.");
    });

    app.MapGet("/api/sinkhole", async (SystemActionService actionService) =>
    {
        var domains = await actionService.GetSinkholedDomains();
        return Results.Json(domains);
    });

    app.MapDelete("/api/sinkhole", async (string domain, SystemActionService actionService) =>
    {
        if (string.IsNullOrEmpty(domain)) return Results.BadRequest("Domain required");
        var success = await actionService.RemoveSinkhole(domain);
        if (success) return Results.Ok(new { message = "Domain removed from sinkhole" });
        return Results.Problem("Failed to remove domain. It may not be in the hosts file or access is denied.");
    });

    app.MapGet("/api/domain-usage", async (string domain, [Microsoft.AspNetCore.Mvc.FromServices] DnsDataService dataService) =>
    {
        var usage = await dataService.GetDomainProcessUsage(domain);
        return Results.Json(usage);
    });

    // Serve static files for React app
    // We will assume the React build output is in 'client/dist' relative to the executable
    var webRoot = Path.Combine(AppContext.BaseDirectory, "client", "dist");
    if (Directory.Exists(webRoot))
    {
        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(webRoot),
            RequestPath = ""
        });
        
        // Fallback to index.html for SPA routing
        app.MapFallbackToFile("index.html", new StaticFileOptions
        {
            FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(webRoot)
        });
    }

    await app.RunAsync($"http://localhost:{cfg.WebPort}");
}

static bool IsAdministrator()
{
    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
    var principal = new System.Security.Principal.WindowsPrincipal(identity);
    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
}

record SinkholeRequest(string Domain);
