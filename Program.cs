using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AsterTele;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║       AsterTele SIP SoftSwitch v1.0      ║");
        Console.WriteLine("║       C# SIP B2BUA Server                ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine();

        var host = Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration(cfg =>
            {
                cfg.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
            })
            .ConfigureServices((context, services) =>
            {
                // 配置绑定
                services.Configure<SipOptions>(context.Configuration.GetSection(SipOptions.SectionName));

                // 接口 → 实现 (Singleton)
                services.AddSingleton<IRegistrationStore, RegistrationStore>();
                services.AddSingleton<ICallManager, CallManager>();
                services.AddSingleton<ITrunkManager, SipTrunkManager>();
                // RTP 基础设施 (从 IOptions<SipOptions> 中提取 RtpOptions)
                services.AddSingleton<RtpPortAllocator>(sp =>
                {
                    var rtpOpts = sp.GetRequiredService<IOptions<SipOptions>>().Value.Rtp;
                    return new RtpPortAllocator(rtpOpts);
                });
                services.AddSingleton<IRtpBridge, NaudioRtpBridge>();

                // DigestAuthenticator 走 DI (需 realm 参数)
                services.AddSingleton<DigestAuthenticator>(sp =>
                    new DigestAuthenticator(
                        sp.GetRequiredService<IOptions<SipOptions>>().Value.Realm,
                        sp.GetService<ILogger<DigestAuthenticator>>()));

                // 共享 SIP 传输上下文
                services.AddSingleton<SipTransportContext>();

                // ByeHandler (先注册, 供 InviteHandler 工厂引用)
                services.AddSingleton<ByeHandler>();

                // InviteHandler 工厂: 需要 ByeHandler.SendByeToCallee 委托
                services.AddSingleton<InviteHandler>(sp =>
                {
                    var byeHandler = sp.GetRequiredService<ByeHandler>();
                    return new InviteHandler(
                        sp.GetRequiredService<SipTransportContext>(),
                        sp.GetRequiredService<ILogger<InviteHandler>>(),
                        sp.GetRequiredService<IOptions<SipOptions>>(),
                        sp.GetRequiredService<ICallManager>(),
                        sp.GetRequiredService<IRegistrationStore>(),
                        sp.GetRequiredService<ITrunkManager>(),
                        sp.GetRequiredService<IRtpBridge>(),
                        (session, reason) => byeHandler.SendByeToCallee(session, reason));
                });

                // 核心服务
                services.AddSingleton<IHostedService, SipSoftSwitch>();
            })
            .ConfigureLogging((context, logging) =>
            {
                logging.AddConsole();
                logging.SetMinimumLevel(LogLevel.Debug);

                // 文件日志: 输出到 exe 同目录下的 logs/ 文件夹
                var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
                Directory.CreateDirectory(logDir);
                var logFile = Path.Combine(logDir, $"astertele_{DateTime.Now:yyyyMMdd_HHmmss}.log");
                logging.AddProvider(new SimpleFileLoggerProvider(logFile));
            })
            .Build();

        // 打印日志文件路径
        var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
        Console.WriteLine($"日志目录: {logDir}");
        Console.WriteLine();

        // 打印注册状态监控
        var cts = new CancellationTokenSource();
        _ = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                await Task.Delay(15000, cts.Token);
                try
                {
                    var store = host.Services.GetRequiredService<IRegistrationStore>();
                    var callMgr = host.Services.GetRequiredService<ICallManager>();
                    var trunkMgr = host.Services.GetRequiredService<ITrunkManager>();

                    var registrations = store.GetAllRegistrations().ToList();
                    var sessions = callMgr.GetActiveSessions().ToList();
                    var trunks = trunkMgr.GetAllTrunkStates().ToList();

                    Console.WriteLine();
                    Console.WriteLine($"── 状态 [{DateTime.Now:HH:mm:ss}] ──");
                    Console.WriteLine($"已注册分机: {registrations.Count}");
                    foreach (var reg in registrations)
                    {
                        var age = DateTime.UtcNow - reg.RegisteredAt;
                        var remaining = reg.Expires - (long)age.TotalSeconds;
                        Console.WriteLine($"  {reg.Number}: Contact={reg.ContactURI} 剩余={remaining}s");
                    }
                    if (trunks.Count > 0)
                    {
                        Console.WriteLine($"SIP Trunk: {trunks.Count}");
                        foreach (var t in trunks)
                        {
                            Console.WriteLine($"  {t.TrunkName}: Registered={t.IsRegistered} Expiry={t.RegisterExpiry}s");
                        }
                    }
                    Console.WriteLine($"活跃通话: {sessions.Count}");
                    foreach (var s in sessions)
                    {
                        var info = s.IsOutboundTrunk ? $" (Trunk:{s.TrunkName})" : "";
                        Console.WriteLine($"  {s.CallerNumber} <-> {s.CalleeNumber}{info} ({s.State})");
                    }
                    Console.WriteLine("─────────────────────────");
                }
                catch { /* ignore monitor errors */ }
            }
        }, cts.Token);

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            await host.RunAsync(cts.Token);
        }
        finally
        {
            cts.Cancel();
        }
    }
}

/// <summary>
/// 简单文件日志 Provider (无第三方依赖)
/// </summary>
internal class SimpleFileLoggerProvider : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly object _lock = new();

    public SimpleFileLoggerProvider(string filePath)
    {
        _writer = new StreamWriter(new FileStream(filePath, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true
        };
    }

    public ILogger CreateLogger(string categoryName) => new SimpleFileLogger(_writer, _lock, categoryName);

    public void Dispose() => _writer.Dispose();
}

internal class SimpleFileLogger : ILogger
{
    private readonly StreamWriter _writer;
    private readonly object _lock;
    private readonly string _category;

    public SimpleFileLogger(StreamWriter writer, object lockObj, string category)
    {
        _writer = writer;
        _lock = lockObj;
        _category = category;
    }

    IDisposable? ILogger.BeginScope<TState>(TState state) => null;
    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Debug;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;
        var msg = $"[{DateTime.Now:HH:mm:ss.fff}] [{logLevel}] [{_category}] {formatter(state, exception)}";
        if (exception != null)
            msg += $"\n{exception}";
        lock (_lock)
        {
            _writer.WriteLine(msg);
        }
    }
}
