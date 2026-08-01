using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SIPSorcery.SIP;
using SIPSorcery.SIP.App;
using System.Net;
using System.Net.Sockets;

namespace AsterTele;

/// <summary>
/// SIP 软交换核心服务 (精简调度器)
/// 职责: 初始化传输层、消息分发、REGISTER/OPTIONS/INFO 处理
/// INVITE/ACK/CANCEL/BYE 等业务逻辑委托给 InviteHandler/ByeHandler
/// </summary>
public class SipSoftSwitch : IHostedService, IDisposable
{
    private readonly ILogger<SipSoftSwitch> _logger;
    private readonly SipOptions _options;
    private readonly RuntimeOptions _runtime;
    private readonly IRegistrationStore _registrationStore;
    private readonly ICallManager _callManager;
    private readonly ITrunkManager _trunkManager;
    private readonly DigestAuthenticator _authenticator;
    private readonly SipTransportContext _ctx;
    private readonly InviteHandler _inviteHandler;
    private readonly ByeHandler _byeHandler;

    private SIPTransport? _sipTransport;
    private Timer? _cleanupTimer;
    private Timer? _sessionCleanupTimer;
    private bool _disposed;

    // 通过 IServiceProvider 解析 internal 类型, 避免在公共构造函数中暴露内部类型
    public SipSoftSwitch(
        IServiceProvider serviceProvider,
        ILogger<SipSoftSwitch> logger,
        IOptions<SipOptions> options,
        IRegistrationStore registrationStore,
        ICallManager callManager,
        ITrunkManager trunkManager,
        DigestAuthenticator authenticator)
    {
        _logger = logger;
        _options = options.Value;
        _runtime = _options.Runtime;
        _registrationStore = registrationStore;
        _callManager = callManager;
        _trunkManager = trunkManager;
        _authenticator = authenticator;
        _ctx = serviceProvider.GetRequiredService<SipTransportContext>();
        _inviteHandler = serviceProvider.GetRequiredService<InviteHandler>();
        _byeHandler = serviceProvider.GetRequiredService<ByeHandler>();
    }

    // ===== IHostedService =====

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("AsterTele SIP 软交换启动中...");
        _logger.LogInformation("监听地址: {Address}:{Port}", _options.ListenAddress, _options.SipPort);
        _logger.LogInformation("认证域: {Realm}", _options.Realm);
        _logger.LogInformation("配置分机: {Extensions}",
            string.Join(", ", _options.Extensions.Select(e => $"{e.Number}({e.DisplayName})")));

        // 初始化 SIP 传输层 (stateless 模式: 禁用事务引擎, 所有消息直接交给应用层)
        _sipTransport = new SIPTransport(stateless: true, Encoding.UTF8, Encoding.UTF8);
        _ctx.Transport = _sipTransport;

        // 创建 UDP 通道
        var listenEP = new IPEndPoint(IPAddress.Any, _options.SipPort);
        var udpChannel = new SIPUDPChannel(listenEP);
        _sipTransport.AddSIPChannel(udpChannel);

        // 注册消息接收事件 (异步委托)
        _sipTransport.SIPTransportRequestReceived += OnSipRequestReceived;
        _sipTransport.SIPTransportResponseReceived += OnSipResponseReceived;

        // Trace 事件: 追踪所有到达的原始 SIP 消息
        _sipTransport.SIPRequestInTraceEvent += (localEP, remoteEP, req) =>
        {
            _logger.LogInformation("[TRACE IN] <<< 请求: {Method} {URI} 从 {Remote} CallId={CallId}",
                req.Method, req.URI, remoteEP, req.Header.CallId);
        };
        _sipTransport.SIPResponseInTraceEvent += (localEP, remoteEP, resp) =>
        {
            _logger.LogInformation("[TRACE IN] <<< 响应: {Status} 从 {Remote} CallId={CallId}",
                resp.Status, remoteEP, resp.Header.CallId);
        };
        _sipTransport.SIPRequestOutTraceEvent += (localEP, remoteEP, req) =>
        {
            _logger.LogInformation("[TRACE OUT] >>> 请求: {Method} {URI} 到 {Remote} CallId={CallId}",
                req.Method, req.URI, remoteEP, req.Header.CallId);
        };
        _sipTransport.SIPResponseOutTraceEvent += (localEP, remoteEP, resp) =>
        {
            _logger.LogInformation("[TRACE OUT] >>> 响应: {Status} 到 {Remote} CallId={CallId}",
                resp.Status, remoteEP, resp.Header.CallId);
        };

        // 初始化对外公布端点 (NAT 穿透支持)
        if (!string.IsNullOrEmpty(_options.AdvertisedAddress))
        {
            var advAddr = IPAddress.Parse(_options.AdvertisedAddress);
            var advPort = _options.AdvertisedPort ?? _options.SipPort;
            _ctx.AdvertisedEP = new SIPEndPoint(SIPProtocolsEnum.udp, advAddr, advPort);
            _logger.LogInformation("对外公布地址: {Address}:{Port} (NAT 模式)", advAddr, advPort);
        }

        // 初始化服务器本地端点
        // 关键: 监听 0.0.0.0 时, SIP 请求的 localEndPoint.Address 恒为 0.0.0.0,
        // 不可用作 Contact/Via/Record-Route 地址, 必须在启动时主动获取真实本机 IP
        // 否则 GetContactEPForClient 对同子网客户端会错误返回 AdvertisedEP (路由器地址),
        // 导致同子网客户端 (如 Zoiper) 的 BYE 发到路由器而非 AsterTele 直连地址
        //
        // 优先使用 MediaAddress 配置值 (通常与 SIP 信令地址相同, 如 192.168.40.102)
        // 只有未配置时才 fallback 到自动探测 (多网卡时可能选错适配器)
        var localIPStr = !string.IsNullOrEmpty(_options.Rtp.MediaAddress)
            ? _options.Rtp.MediaAddress
            : NetworkUtility.GetLocalIPv4();
        _ctx.LocalEP = new SIPEndPoint(SIPProtocolsEnum.udp,
            IPAddress.Parse(localIPStr), _options.SipPort);
        _logger.LogInformation("服务器本地地址: {Address}:{Port} (来源: {Source})",
            _ctx.LocalEP.Address, _ctx.LocalEP.Port,
            !string.IsNullOrEmpty(_options.Rtp.MediaAddress) ? "MediaAddress 配置" : "自动探测");

        // 启动定时清理过期注册
        _cleanupTimer = new Timer(_ => _registrationStore.CleanupExpired(), null,
            TimeSpan.FromSeconds(_runtime.RegistrationCleanupIntervalSeconds),
            TimeSpan.FromSeconds(_runtime.RegistrationCleanupIntervalSeconds));

        // 启动定时清理幽灵会话 (委托给 ByeHandler)
        _sessionCleanupTimer = new Timer(_ => _byeHandler.CleanupStaleSessions(), null,
            TimeSpan.FromSeconds(_runtime.SessionCleanupIntervalSeconds),
            TimeSpan.FromSeconds(_runtime.SessionCleanupIntervalSeconds));

        _logger.LogInformation("AsterTele SIP 软交换已启动，端口 {Port}", _options.SipPort);

        // 绑定 SIP Trunk 管理器
        if (_options.Trunks.Any(t => t.Enabled))
        {
            _trunkManager.BindTransport(_sipTransport);
            _ = _trunkManager.StartAllRegistrations();
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("AsterTele SIP 软交换正在停止...");
        _cleanupTimer?.Dispose();
        _sessionCleanupTimer?.Dispose();
        _sipTransport?.Shutdown();
        _logger.LogInformation("AsterTele SIP 软交换已停止");
        return Task.CompletedTask;
    }

    // ===== SIP 消息分发 =====

    private async Task OnSipRequestReceived(
        SIPEndPoint localEndPoint,
        SIPEndPoint remoteEndPoint,
        SIPRequest sipRequest)
    {
        try
        {
            // 如果尚未设置公布地址, 从第一个到达的请求推断
            if (_ctx.AdvertisedEP == SIPEndPoint.Empty)
            {
                _ctx.AdvertisedEP = new SIPEndPoint(SIPProtocolsEnum.udp,
                    localEndPoint.Address, _options.SipPort);
                _logger.LogInformation("推断对外公布地址: {Address}:{Port}",
                    _ctx.AdvertisedEP.Address, _ctx.AdvertisedEP.Port);
            }

            // LocalEP 已在 StartAsync 中用 GetLocalIPv4() 初始化
            // 不再从 localEndPoint.Address 推断 (监听 0.0.0.0 时恒为 0.0.0.0)

            _logger.LogDebug("<<< SIP 请求: {Method} {URI} 从 {Remote}",
                sipRequest.Method, sipRequest.URI, remoteEndPoint);

            switch (sipRequest.Method)
            {
                case SIPMethodsEnum.REGISTER:
                    await HandleRegister(sipRequest, remoteEndPoint);
                    break;
                case SIPMethodsEnum.INVITE:
                    await _inviteHandler.HandleInvite(sipRequest, localEndPoint, remoteEndPoint);
                    break;
                case SIPMethodsEnum.ACK:
                    await _inviteHandler.HandleAck(sipRequest, localEndPoint, remoteEndPoint);
                    break;
                case SIPMethodsEnum.BYE:
                    await _byeHandler.HandleBye(sipRequest, localEndPoint, remoteEndPoint);
                    break;
                case SIPMethodsEnum.CANCEL:
                    await _inviteHandler.HandleCancel(sipRequest, localEndPoint, remoteEndPoint);
                    break;
                case SIPMethodsEnum.OPTIONS:
                    await HandleOptions(sipRequest, remoteEndPoint);
                    break;
                case SIPMethodsEnum.INFO:
                    await HandleInfo(sipRequest, remoteEndPoint);
                    break;
                default:
                    _logger.LogWarning("不支持的方法: {Method}", sipRequest.Method);
                    await SendResponse(sipRequest, SIPResponseStatusCodesEnum.MethodNotAllowed, "Method Not Allowed", remoteEndPoint);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "处理 SIP 请求异常: {Method} {URI}", sipRequest.Method, sipRequest.URI);
        }
    }

    private async Task OnSipResponseReceived(
        SIPEndPoint localEndPoint,
        SIPEndPoint remoteEndPoint,
        SIPResponse sipResponse)
    {
        try
        {
            _logger.LogDebug("<<< SIP 响应: {Status} {Reason} CallId={CallId}",
                sipResponse.Status, sipResponse.ReasonPhrase, sipResponse.Header.CallId);

            // 过滤 REGISTER 响应 (由 SipTrunkManager.OnTrunkResponse 处理)
            if (sipResponse.Header.CSeqMethod == SIPMethodsEnum.REGISTER)
                return;

            // 处理 BYE 的 200 OK 响应
            if (sipResponse.Status == SIPResponseStatusCodesEnum.Ok &&
                sipResponse.Header.CSeqMethod == SIPMethodsEnum.BYE)
            {
                await _byeHandler.HandleBye200Ok(sipResponse);
                return;
            }

            // 处理外呼 INVITE 的 401 挑战 (运营商要求 Digest 认证)
            if (sipResponse.Status == SIPResponseStatusCodesEnum.Unauthorised &&
                sipResponse.Header.CSeqMethod == SIPMethodsEnum.INVITE)
            {
                var outboundSession = _callManager.FindByCalleeCallId(sipResponse.Header.CallId);
                if (outboundSession != null && outboundSession.IsOutboundTrunk)
                {
                    _logger.LogInformation("外呼 INVITE 收到 401 挑战, 重新认证 (CallId={CallId})",
                        sipResponse.Header.CallId);
                    await _inviteHandler.HandleOutboundInviteAuthChallenge(outboundSession, sipResponse, remoteEndPoint);
                    return;
                }
            }

            // B2BUA: 将被叫侧 INVITE 响应转发给主叫侧
            await _inviteHandler.ForwardCalleeResponse(sipResponse, localEndPoint, remoteEndPoint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "处理 SIP 响应异常: Status={Status}", sipResponse.Status);
        }
    }

    // ===== REGISTER 处理 =====

    private async Task HandleRegister(SIPRequest request, SIPEndPoint remoteEP)
    {
        // ===== Trunk REGISTER 回环检测 =====
        var extensionNumber = request.Header.To.ToURI.User;
        var requestUriHost = request.URI.HostAddress;

        if (_options.Trunks.Any(t => t.Enabled))
        {
            var isTrunkLoop = _options.Trunks.Any(t =>
            {
                var trunkUri = SIPURI.ParseSIPURI(t.Registrar.StartsWith("sip:") ? t.Registrar : $"sip:{t.Registrar}");
                return requestUriHost == trunkUri.HostAddress
                       && t.Username.StartsWith(extensionNumber);
            });

            if (isTrunkLoop)
            {
                _logger.LogWarning("Trunk REGISTER 回环检测: 忽略 (分机={Number}, URI={URI})", extensionNumber, request.URI);
                return;
            }
        }

        if (string.IsNullOrEmpty(extensionNumber))
        {
            await SendResponse(request, SIPResponseStatusCodesEnum.BadRequest, "Missing extension", remoteEP);
            return;
        }

        _logger.LogInformation("REGISTER 请求: 分机={Number} 从={Remote}", extensionNumber, remoteEP);

        // 检查分机是否存在
        if (!_registrationStore.ExtensionExists(extensionNumber))
        {
            _logger.LogWarning("未知分机: {Number}", extensionNumber);
            await SendResponse(request, SIPResponseStatusCodesEnum.NotFound, "Extension not found", remoteEP);
            return;
        }

        // 检查是否携带了 Authorization 头
        var authHeaders = request.Header.AuthenticationHeaders;
        if (authHeaders == null || authHeaders.Count == 0 ||
            authHeaders[0].SIPDigest == null || string.IsNullOrEmpty(authHeaders[0].SIPDigest.Response))
        {
            // 第一次 REGISTER，发送 401 挑战
            _logger.LogDebug("发送 401 Digest 挑战给分机 {Number}", extensionNumber);
            var challengeResponse = _authenticator.Challenge(request);
            await _ctx.Transport!.SendResponseAsync(remoteEP, challengeResponse);
            return;
        }

        // 验证 Digest 认证
        var extConfig = _registrationStore.GetExtensionConfig(extensionNumber);
        if (extConfig == null)
        {
            await SendResponse(request, SIPResponseStatusCodesEnum.NotFound, "Extension not found", remoteEP);
            return;
        }

        // 诊断日志: 打印客户端的 Digest 参数
        var clientDigest = authHeaders[0].SIPDigest;
        _logger.LogDebug(
            "Digest 认证参数: 分机={Number}, Username={Username}, Realm={Realm}, Nonce={Nonce}, " +
            "URI={URI}, Qop={Qop}, Cnonce={Cnonce}, NC={NC}, Response={Response}, Method={Method}",
            extensionNumber, request.Header.From.FromURI.User ?? "?",
            clientDigest?.Realm ?? "?", clientDigest?.Nonce?[..Math.Min(8, clientDigest.Nonce.Length)] ?? "?",
            clientDigest?.URI ?? "?", clientDigest?.Qop ?? "?",
            clientDigest?.Cnonce ?? "?", clientDigest?.NonceCount.ToString() ?? "?",
            clientDigest?.Response?[..Math.Min(8, clientDigest.Response.Length)] ?? "?",
            request.Method);

        if (!_authenticator.Validate(request, extensionNumber, extConfig.Password))
        {
            _logger.LogWarning("分机 {Number} 认证失败", extensionNumber);
            await SendResponse(request, SIPResponseStatusCodesEnum.Forbidden, "Authentication failed", remoteEP);
            return;
        }

        // 认证成功，处理注册
        var contactHeader = request.Header.Contact.FirstOrDefault();
        if (contactHeader == null)
        {
            await SendResponse(request, SIPResponseStatusCodesEnum.BadRequest, "Missing Contact header", remoteEP);
            return;
        }

        // 提取 expires
        long expires = _options.RegisterExpiry;
        if (contactHeader.Expires > 0)
            expires = contactHeader.Expires;
        else if (request.Header.Expires > 0)
            expires = request.Header.Expires;

        // expires=0 表示注销
        if (expires == 0)
        {
            _registrationStore.Unregister(extensionNumber);
            await SendResponse(request, SIPResponseStatusCodesEnum.Ok, "Unregistered", remoteEP);
            _logger.LogInformation("分机 {Number} 已注销", extensionNumber);
            return;
        }

        // 存储注册信息
        var registration = new RegisteredExtension
        {
            Number = extensionNumber,
            Password = extConfig.Password,
            DisplayName = extConfig.DisplayName,
            ContactURI = contactHeader.ContactURI.CopyOf(),
            SourceEndPoint = remoteEP.CopyOf(),
            RegisteredAt = DateTime.UtcNow,
            Expires = expires,
            CallId = request.Header.CallId
        };

        _registrationStore.Register(registration);

        // 200 OK
        var okResponse = SIPResponse.GetResponse(request, SIPResponseStatusCodesEnum.Ok, "OK");
        okResponse.Header.Contact = request.Header.Contact;
        okResponse.Header.Expires = expires;
        await _ctx.Transport!.SendResponseAsync(remoteEP, okResponse);

        _logger.LogInformation("分机 {Number} 注册成功: Contact={Contact}, Expires={Expires}s",
            extensionNumber, contactHeader.ContactURI, expires);
    }

    // ===== OPTIONS 处理 =====

    private async Task HandleOptions(SIPRequest request, SIPEndPoint remoteEP)
    {
        _logger.LogDebug("OPTIONS: 从 {Remote}", remoteEP);
        await SendResponse(request, SIPResponseStatusCodesEnum.Ok, "OK", remoteEP);
    }

    // ===== INFO 处理 =====

    private async Task HandleInfo(SIPRequest request, SIPEndPoint remoteEP)
    {
        _logger.LogDebug("INFO: 从 {Remote}, Content-Type={ContentType}", remoteEP, request.Header.ContentType);

        // 尝试解析 DTMF
        string? dtmfDigit = null;

        if (!string.IsNullOrEmpty(request.Body))
        {
            if (request.Header.ContentType?.Contains("dtmf-relay") == true)
            {
                var match = System.Text.RegularExpressions.Regex.Match(request.Body, @"Signal\s*=\s*(\S)");
                if (match.Success)
                    dtmfDigit = match.Groups[1].Value;
            }
            else if (request.Header.ContentType?.Contains("dtmf") == true)
            {
                dtmfDigit = request.Body.Trim();
            }
        }

        if (dtmfDigit != null)
        {
            _logger.LogInformation("DTMF 收到: digit={Digit} (来源: {Remote})", dtmfDigit, remoteEP);
            // TODO: 将 DTMF 转发给 IVR 会话管理器
        }

        // 回 200 OK
        await SendResponse(request, SIPResponseStatusCodesEnum.Ok, "OK", remoteEP);
    }

    // ===== 辅助方法 =====

    private async Task SendResponse(SIPRequest request, SIPResponseStatusCodesEnum status, string reason, SIPEndPoint remoteEP)
    {
        var response = SIPResponse.GetResponse(request, status, reason);
        await _ctx.Transport!.SendResponseAsync(remoteEP, response);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _cleanupTimer?.Dispose();
            _sessionCleanupTimer?.Dispose();
            _sipTransport?.Shutdown();
        }
    }
}
