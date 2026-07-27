using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SIPSorcery.SIP;
using SIPSorcery.SIP.App;
using System.Net;
using System.Net.Sockets;

namespace AsterTele;

/// <summary>
/// SIP 软交换核心服务
/// 基于 SIPSorcery 实现 REGISTER / INVITE / BYE / CANCEL / OPTIONS 处理
/// 工作模式: B2BUA (Back-to-Back User Agent)
/// </summary>
public class SipSoftSwitch : IHostedService, IDisposable
{
    /// <summary>最大呼叫转移深度 (防止无限循环)</summary>
    private const int MaxForwardDepth = 5;

    private readonly ILogger<SipSoftSwitch> _logger;
    private readonly SipOptions _options;
    private readonly RegistrationStore _registrationStore;
    private readonly CallManager _callManager;
    private readonly SipTrunkManager _trunkManager;
    private readonly DigestAuthenticator _authenticator;

    private SIPTransport? _sipTransport;
    private Timer? _cleanupTimer;
    private Timer? _sessionCleanupTimer;
    private bool _disposed;

    /// <summary>
    /// 对外公布端点 (NAT 场景下为路由器 IP, 否则为服务器本机 IP)
    /// 用于跨子网客户端的 Contact / Via / Record-Route
    /// </summary>
    private SIPEndPoint _advertisedEP = SIPEndPoint.Empty;

    /// <summary>
    /// 服务器本地端点 (从实际到达的请求推断)
    /// 用于同子网客户端的 Contact / Record-Route 直连路由
    /// </summary>
    private SIPEndPoint _localEP = SIPEndPoint.Empty;

    public SipSoftSwitch(
        ILogger<SipSoftSwitch> logger,
        IOptions<SipOptions> options,
        RegistrationStore registrationStore,
        CallManager callManager,
        SipTrunkManager trunkManager)
    {
        _logger = logger;
        _options = options.Value;
        _registrationStore = registrationStore;
        _callManager = callManager;
        _trunkManager = trunkManager;
        _callManager = callManager;
        _authenticator = new DigestAuthenticator(_options.Realm);
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
        // 必须用 stateless, 否则 SIPSorcery 的 UAS 事务会自动消耗 ACK/BYE, 不触发事件
        _sipTransport = new SIPTransport(stateless: true, Encoding.UTF8, Encoding.UTF8);

        // 创建 UDP 通道
        var listenEP = new IPEndPoint(IPAddress.Any, _options.SipPort);
        var udpChannel = new SIPUDPChannel(listenEP);
        _sipTransport.AddSIPChannel(udpChannel);

        // 注册消息接收事件 (异步委托)
        _sipTransport.SIPTransportRequestReceived += OnSipRequestReceived;
        _sipTransport.SIPTransportResponseReceived += OnSipResponseReceived;

        // Trace 事件: 追踪所有到达的原始 SIP 消息 (包括事务匹配的)
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
        // 如果配置了 AdvertisedAddress, 使用它; 否则在第一个请求到达时从 localEP 推断
        if (!string.IsNullOrEmpty(_options.AdvertisedAddress))
        {
            var advAddr = IPAddress.Parse(_options.AdvertisedAddress);
            var advPort = _options.AdvertisedPort ?? _options.SipPort;
            _advertisedEP = new SIPEndPoint(SIPProtocolsEnum.udp, advAddr, advPort);
            _logger.LogInformation("对外公布地址: {Address}:{Port} (NAT 模式)", advAddr, advPort);
        }

        // 启动定时清理过期注册
        _cleanupTimer = new Timer(_ => _registrationStore.CleanupExpired(), null,
            TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));

        // 启动定时清理幽灵会话 (超过 2 分钟仍处于 Initiating/Ringing 的会话)
        _sessionCleanupTimer = new Timer(_ => CleanupStaleSessions(), null,
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));

        _logger.LogInformation("AsterTele SIP 软交换已启动，端口 {Port}", _options.SipPort);

        // 绑定 SIP Trunk 管理器 (REGISTER + 外呼 INVITE 都走主 transport 5060 端口)
        // 外呼 INVITE 的响应 (180/200 OK) 由主 transport 的 OnSipResponseReceived 统一处理
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

    // ===== SIP 消息接收 =====

    private async Task OnSipRequestReceived(
        SIPEndPoint localEndPoint,
        SIPEndPoint remoteEndPoint,
        SIPRequest sipRequest)
    {
        try
        {
            // 如果尚未设置公布地址, 从第一个到达的请求推断
            if (_advertisedEP == SIPEndPoint.Empty)
            {
                _advertisedEP = new SIPEndPoint(SIPProtocolsEnum.udp,
                    localEndPoint.Address, _options.SipPort);
                _logger.LogInformation("推断对外公布地址: {Address}:{Port}",
                    _advertisedEP.Address, _advertisedEP.Port);
            }

            // 记录服务器本地端点 (用于同子网客户端直连路由)
            if (_localEP == SIPEndPoint.Empty)
            {
                _localEP = new SIPEndPoint(SIPProtocolsEnum.udp,
                    localEndPoint.Address, _options.SipPort);
                _logger.LogInformation("服务器本地地址: {Address}:{Port}",
                    _localEP.Address, _localEP.Port);
            }

            _logger.LogDebug("<<< SIP 请求: {Method} {URI} 从 {Remote}",
                sipRequest.Method, sipRequest.URI, remoteEndPoint);

            switch (sipRequest.Method)
            {
                case SIPMethodsEnum.REGISTER:
                    await HandleRegister(sipRequest, localEndPoint, remoteEndPoint);
                    break;

                case SIPMethodsEnum.INVITE:
                    await HandleInvite(sipRequest, localEndPoint, remoteEndPoint);
                    break;

                case SIPMethodsEnum.ACK:
                    await HandleAck(sipRequest, localEndPoint, remoteEndPoint);
                    break;

                case SIPMethodsEnum.BYE:
                    await HandleBye(sipRequest, localEndPoint, remoteEndPoint);
                    break;

                case SIPMethodsEnum.CANCEL:
                    await HandleCancel(sipRequest, localEndPoint, remoteEndPoint);
                    break;

                case SIPMethodsEnum.OPTIONS:
                    await HandleOptions(sipRequest, localEndPoint, remoteEndPoint);
                    break;

                case SIPMethodsEnum.INFO:
                    await HandleInfo(sipRequest, localEndPoint, remoteEndPoint);
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

            // 处理 BYE 的 200 OK 响应 (服务端主动发出的 BYE 得到对端确认)
            if (sipResponse.Status == SIPResponseStatusCodesEnum.Ok &&
                sipResponse.Header.CSeqMethod == SIPMethodsEnum.BYE)
            {
                await HandleBye200Ok(sipResponse);
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
                    await HandleOutboundInviteAuthChallenge(outboundSession, sipResponse, remoteEndPoint);
                    return;
                }
            }

            // B2BUA: 将被叫侧 INVITE 响应转发给主叫侧
            await ForwardCalleeResponse(sipResponse, localEndPoint, remoteEndPoint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "处理 SIP 响应异常: Status={Status}", sipResponse.Status);
        }
    }

    // ===== REGISTER 处理 =====

    private async Task HandleRegister(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        // ===== Trunk REGISTER 回环检测 =====
        // 路由器可能把 Trunk 专用端口发出的 REGISTER 经 NAT 转发弹回主端口 5060
        // 检测方式: 如果 REGISTER 的 Request-URI 指向 Trunk Registrar 且本地没有该分机, 则是回环
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
                // 不回任何响应, 否则 SipTrunkManager 会误处理
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
            await _sipTransport!.SendResponseAsync(remoteEP, challengeResponse);
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
            _logger.LogWarning("分机 {Number} 认证失败 (期望密码={Pwd})", extensionNumber, extConfig.Password);
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
        await _sipTransport!.SendResponseAsync(remoteEP, okResponse);

        _logger.LogInformation("分机 {Number} 注册成功: Contact={Contact}, Expires={Expires}s",
            extensionNumber, contactHeader.ContactURI, expires);
    }

    // ===== INVITE 处理 =====

    private async Task HandleInvite(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {

        // 从 From 头提取主叫分机号
        var callerNumber = request.Header.From.FromURI.User;
        // 从 Request-URI 提取被叫分机号
        var calleeNumber = request.URI.User;

        // 运营商入站 INVITE 的 From URI 可能无 user 部分 (如 sip:172.26.160.38)
        // 使用整个 From URI 作为 fallback, 避免 null 传入 ConcurrentDictionary
        callerNumber ??= request.Header.From.FromURI.Host ?? "unknown";
        calleeNumber ??= request.URI.Host ?? "unknown";

        _logger.LogInformation("INVITE: {Caller} -> {Callee}", callerNumber, calleeNumber);

        // 打印完整 INVITE 报文 (Info 级别, 便于排查运营商入站/外呼路由问题)
        _logger.LogInformation("INVITE 报文:\n{Packet}", request.ToString());

        _logger.LogDebug("INVITE SDP:\n{Sdp}", string.IsNullOrEmpty(request.Body) ? "(无 SDP)" : request.Body);

        // === re-INVITE / in-dialog INVITE 检测 ===
        // 运营商在通话建立后可能发 re-INVITE (同 Call-ID, CSeq 递增)
        // 这是 in-dialog 请求, 不应创建新会话
        var existingByCaller = _callManager.FindByCallerCallId(request.Header.CallId);
        var existingByCallee = _callManager.FindByCalleeCallId(request.Header.CallId);

        if (existingByCaller != null || existingByCallee != null)
        {
            var existingSession = existingByCaller ?? existingByCallee!;

            // 同一 Call-ID 且 CSeq > 原始 INVITE → re-INVITE (in-dialog)
            // 同一 Call-ID 且 CSeq = 原始 INVITE → 重传
            if (existingByCaller != null)
            {
                // 区分重传 vs re-INVITE: 比较 CSeq 序号
                var incomingCSeq = request.Header.CSeq;
                var originalCSeq = existingByCaller.CallerInviteCSeq;

                if (incomingCSeq == originalCSeq)
                {
                    // 真正的重传: CSeq 相同, 回复缓存的响应
                    _logger.LogInformation("INVITE 重传 (主叫侧): CallId={CallId}, CSeq={CSeq}, 回复缓存的响应",
                        request.Header.CallId, incomingCSeq);
                    await SendResponse(request, SIPResponseStatusCodesEnum.Trying, "Trying", remoteEP);
                    if (existingSession.ForwardedCallerOkResponse != null)
                        await _sipTransport!.SendResponseAsync(existingSession.CallerRemoteEP, existingSession.ForwardedCallerOkResponse);
                    return;
                }

                if (incomingCSeq > originalCSeq)
                {
                    // re-INVITE: CSeq 递增, 同一条 dialog 内的新请求
                    _logger.LogInformation("re-INVITE (主叫侧 CSeq 递增): CallId={CallId}, CSeq={CSeq} > 原CSeq={OrigCSeq}, 会话={SessionId}",
                        request.Header.CallId, incomingCSeq, originalCSeq, existingSession.SessionId);

                    // 更新缓存的 CSeq, 避免后续同一 dialog 的 re-INVITE 被误判
                    existingByCaller.CallerInviteCSeq = incomingCSeq;

                    await SendResponse(request, SIPResponseStatusCodesEnum.Trying, "Trying", remoteEP);
                    await HandleTrunkReInvite(request, existingSession, remoteEP);
                    return;
                }

                // CSeq < 原始 (异常情况, 可能是乱序报文)
                _logger.LogWarning("INVITE CSeq 异常 (低于原始): CallId={CallId}, CSeq={CSeq} < 原CSeq={OrigCSeq}, 忽略",
                    request.Header.CallId, incomingCSeq, originalCSeq);
                return;
            }

            // 被叫侧收到同一 Call-ID 的 INVITE → 这是运营商发来的 re-INVITE
            _logger.LogInformation("re-INVITE (in-dialog): CallId={CallId}, CSeq={CSeq}, 会话={SessionId}",
                request.Header.CallId, request.Header.CSeq, existingSession.SessionId);

            // 回复 100 Trying
            await SendResponse(request, SIPResponseStatusCodesEnum.Trying, "Trying", remoteEP);

            // 如果是 Trunk 入站会话 (运营商 -> 本地分机), 需要把 re-INVITE 转发给本地分机
            if (existingSession.IsOutboundTrunk)
            {
                // 外呼方向的 re-INVITE: 运营商要求修改会话参数
                // 简单处理: 回 200 OK + 之前的 SDP (拒绝修改, 保持原会话)
                _logger.LogInformation("外呼方向 re-INVITE: 回 200 OK 保持原会话");
                await HandleTrunkReInvite(request, existingSession, remoteEP);
            }
            else
            {
                // 入站方向的 re-INVITE: 运营商要求修改会话
                // 简单处理: 回 200 OK + 之前的 SDP (拒绝修改, 保持原会话)
                _logger.LogInformation("入站方向 re-INVITE: 回 200 OK 保持原会话");
                await HandleTrunkReInvite(request, existingSession, remoteEP);
            }

            return;
        }

        // ===== 路由决策 =====

        // 判断是否来自 SIP Trunk (运营商 IP 或来自已注册 Trunk 的请求)
        var isFromTrunk = _options.Trunks.Any(t =>
            t.Enabled && IsFromTrunkNetwork(remoteEP));

        // 1. 外呼路由：被叫号码匹配拨号前缀 (如 "9" 开头) → 通过 SIP Trunk 外呼
        var (outboundTrunk, outboundRoute) = _trunkManager.ResolveOutboundRoute(calleeNumber);
        if (outboundTrunk != null && outboundRoute != null)
        {
            _logger.LogInformation("外呼路由匹配: {Callee} → Trunk={TrunkName}, StripPrefix={Strip}",
                calleeNumber, outboundTrunk.Name, outboundRoute.StripPrefix);
            await HandleOutboundInvite(request, remoteEP, callerNumber, calleeNumber, outboundTrunk, outboundRoute);
            return;
        }

        // 2. 入站 DID 路由：被叫号码匹配 DID 映射 → 转到本地分机或 IVR
        var didMapping = _trunkManager.ResolveDidMapping(calleeNumber);
        if (didMapping != null)
        {
            _logger.LogInformation("入站 DID 匹配: {Did} → {Type} {Target}",
                calleeNumber, didMapping.MappingType,
                didMapping.MappingType == DidMappingType.Direct ? didMapping.TargetExtension : "IVR");

            if (didMapping.MappingType == DidMappingType.Direct && !string.IsNullOrEmpty(didMapping.TargetExtension))
            {
                // 重写被叫号为本地分机号
                calleeNumber = didMapping.TargetExtension;
            }
            else if (didMapping.MappingType == DidMappingType.IVR)
            {
                // IVR 模式: 当前骨架阶段, 无法播放提示音 (需 RTP 音频)
                // 实际行为: 直接路由到 DID 映射的默认目标 (如有), 否则返回 503
                _logger.LogInformation("IVR 二次拨号: DID={Did}, 前缀={Prefix} (RTP 音频待实现)",
                    calleeNumber, didMapping.IvrPrefix ?? "8");

                // TODO: 完整 IVR 流程 (需 RTP 音频 + DTMF 支持)
                // 1. 应答呼叫 (200 OK + SDP)
                // 2. 播放提示音 ("请拨打 8xxx")
                // 3. 收集 DTMF 拨号 (SIP INFO / RFC 2833)
                // 4. 匹配分机号后发起转接

                // 骨架: 如果 TargetExtension 有值, 直接路由; 否则返回 503
                if (!string.IsNullOrEmpty(didMapping.TargetExtension))
                {
                    _logger.LogInformation("IVR 骨架: 直接路由到默认目标 {Target} (跳过 DTMF 收集)", didMapping.TargetExtension);
                    calleeNumber = didMapping.TargetExtension;
                    // 继续走正常路由流程 (下方无条件转移 + 本地分机路由)
                }
                else
                {
                    await SendResponse(request, SIPResponseStatusCodesEnum.ServiceUnavailable,
                        "IVR audio not implemented yet", remoteEP);
                    return;
                }
            }
        }

        // 3. 呼叫转移：检查被叫是否配置了无条件转移
        var forwardRule = _trunkManager.ResolveForwardRule(calleeNumber, CallForwardType.Unconditional);
        if (forwardRule != null)
        {
            _logger.LogInformation("无条件转移: {From} → {To}", calleeNumber, forwardRule.Target);
            calleeNumber = forwardRule.Target;
        }

        // 4. 本地分机路由
        var callerReg = _registrationStore.GetRegistration(callerNumber);
        if (callerReg == null)
        {
            // 检查是否是来自 SIP Trunk 的入站呼叫 (主叫不在本地注册表中)
            // 条件: 来自 Trunk 运营商 IP 或已匹配 DID 映射
            if (didMapping == null && !isFromTrunk)
            {
                _logger.LogWarning("主叫分机 {Number} 未注册且非 Trunk 入站", callerNumber);
                await SendResponse(request, SIPResponseStatusCodesEnum.Forbidden, "Not registered", remoteEP);
                return;
            }

            // Trunk 入站但未配置 DID 映射 — 无法路由
            if (didMapping == null)
            {
                _logger.LogWarning("Trunk 入站呼叫: 被叫 {Number} 无 DID 映射, 无法路由到本地分机", calleeNumber);
                await SendResponse(request, SIPResponseStatusCodesEnum.NotFound, "No DID mapping", remoteEP);
                return;
            }

            // Trunk 入站呼叫，主叫不要求注册
            callerReg = new RegisteredExtension
            {
                Number = callerNumber,
                ContactURI = request.Header.From.FromURI.CopyOf(),
                SourceEndPoint = remoteEP.CopyOf()
            };
        }

        var calleeReg = _registrationStore.GetRegistration(calleeNumber);
        if (calleeReg == null)
        {
            _logger.LogWarning("被叫分机 {Number} 未注册", calleeNumber);
            await SendResponse(request, SIPResponseStatusCodesEnum.NotFound, "Extension not found", remoteEP);
            return;
        }

        // 清理主叫和被叫已有的旧会话 (防止幽灵会话累积)
        _callManager.RemoveSessionByExtension(callerNumber);
        _callManager.RemoveSessionByExtension(calleeNumber);

        // 发送 100 Trying 给主叫
        await SendResponse(request, SIPResponseStatusCodesEnum.Trying, "Trying", remoteEP);

        // 创建 B2BUA 呼叫会话
        var session = _callManager.CreateSession(callerNumber, calleeNumber, request, remoteEP);
        session.CallerFromTag = request.Header.From.FromTag;
        session.CallerInviteCSeq = request.Header.CSeq;

        // 保存主叫侧 Contact URI (用于后续发 BYE)
        var callerContact = request.Header.Contact.FirstOrDefault();
        if (callerContact != null)
            session.CallerContactURI = callerContact.ContactURI.CopyOf();

        // 创建向被叫侧的 INVITE (B2BUA 新 Call-ID, 新 From tag, 新 Via)
        // 根据被叫网络选择 Contact/Record-Route 地址 (同子网直连, 跨子网走路由器)
        var calleeTargetEP = GetContactEPForClient(new SIPEndPoint(SIPProtocolsEnum.udp,
            calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port));
        var calleeInvite = CreateB2BUAInvite(request, calleeReg, calleeTargetEP);

        // 发送 INVITE 给被叫
        try
        {
            _logger.LogInformation("向被叫 {Number} ({Contact}) 发送 INVITE", calleeNumber, calleeReg.ContactURI);
            var calleeEP = new SIPEndPoint(SIPProtocolsEnum.udp,
                calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port);
            await _sipTransport!.SendRequestAsync(calleeEP, calleeInvite);
            _callManager.RegisterCalleeLeg(session, calleeInvite, calleeEP);

            // 启动无应答超时定时器 (如果被叫配置了 NoAnswer 转移)
            StartNoAnswerTimer(session);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "向被叫 {Number} 发送 INVITE 失败", calleeNumber);
            await SendResponse(request, SIPResponseStatusCodesEnum.ServiceUnavailable, "Destination unreachable", remoteEP);
            _callManager.RemoveSession(session);
        }
    }

    /// <summary>
    /// 处理外呼 INVITE：通过 SIP Trunk 将呼叫转发到运营商网关
    /// </summary>
    private async Task HandleOutboundInvite(SIPRequest request, SIPEndPoint callerEP,
        string callerNumber, string calleeNumber, SipTrunkConfig trunk, DialRouteRule route)
    {
        if (_sipTransport == null) return;

        // 剥除前缀 (如拨 9138xxxx → 138xxxx)
        var actualNumber = route.StripPrefix ? calleeNumber[route.Prefix.Length..] : calleeNumber;

        _logger.LogInformation("外呼: {Caller} → {ActualNumber} (via Trunk {TrunkName})",
            callerNumber, actualNumber, trunk.Name);

        // 发送 100 Trying
        await SendResponse(request, SIPResponseStatusCodesEnum.Trying, "Trying", callerEP);

        // 创建 B2BUA 会话
        var session = _callManager.CreateSession(callerNumber, actualNumber, request, callerEP);
        session.CallerFromTag = request.Header.From.FromTag;
        session.CallerInviteCSeq = request.Header.CSeq;
        session.IsOutboundTrunk = true;
        session.TrunkName = trunk.Name;

        // 保存主叫侧 Contact URI (本地分机的 Contact, 用于后续发 BYE)
        var outboundCallerContact = request.Header.Contact.FirstOrDefault();
        if (outboundCallerContact != null)
            session.CallerContactURI = outboundCallerContact.ContactURI.CopyOf();

        // 构建向运营商网关的 INVITE
        var trunkRegistrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
            ? trunk.Registrar : $"sip:{trunk.Registrar}");
        var trunkEP = ResolveSipUriEndPoint(trunkRegistrarUri);

        // 使用 Trunk 的 OutboundAddress 作为 Contact/SDP 地址 (运营商侧看到的公网 IP)
        // Via sent-by 使用内网 IP + trunk 传输层实际端口 (MicroSIP 抓包确认)
        var (trunkOutIp, _) = _trunkManager.GetOutboundAddress(trunk);
        var trunkTransportEP = _trunkManager.GetTrunkTransportEP();

        // Via sent-by: 使用本机内网 IP + trunk 传输层端口
        var localIP = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                      && ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                      && !System.Net.IPAddress.IsLoopback(ua.Address)
                      && !ua.Address.Equals(System.Net.IPAddress.Any))
            .Select(ua => ua.Address.ToString())
            .FirstOrDefault() ?? "127.0.0.1";
        var trunkViaEP = new SIPEndPoint(SIPProtocolsEnum.udp,
            System.Net.IPAddress.Parse(localIP), trunkTransportEP.Port);

        // === 中国电信 IMS 外呼 INVITE 格式要求 ===
        // Request-URI: 使用 tel: 格式 (如 tel:+8610000), 运营商 IMS 期望此格式
        // To: 使用 sip: 格式 (sip:10000@bac26.cq.ctcims.cn)
        // From: 使用 sip: 格式, user=主叫号码 (或 Trunk 号码)
        var trunkNumber = trunk.FromUser ?? trunk.Username.Split('@')[0];

        // Request-URI: tel:+86<号码> 格式 (中国电信 IMS 要求)
        // 如果号码不以 +86 开头且长度 >= 5, 自动添加 +86 前缀
        var outboundNumber = actualNumber;
        if (!outboundNumber.StartsWith("+") && outboundNumber.Length >= 5)
            outboundNumber = "+86" + outboundNumber;

        var calleeRequestUri = new SIPURI(outboundNumber, trunkOutIp, null, SIPSchemesEnum.sip);
        // 重写为 tel: URI — SIPSorcery SIPURI 不直接支持 tel:, 用字符串构造
        // 实际报文行: INVITE tel:+8610000 SIP/2.0
        var trunkInvite = SIPRequest.GetRequest(SIPMethodsEnum.INVITE, calleeRequestUri);

        // 手动替换 Request-URI 为 tel: 格式 (SIPSorcery 不原生支持 tel: URI)
        trunkInvite.URI = SIPURI.ParseSIPURI($"tel:{outboundNumber}");

        // 清除 GetRequest 自动添加的默认 Via (0.0.0.0), 替换为内网 IP + trunk 端口
        trunkInvite.Header.Vias.Via.Clear();
        trunkInvite.Header.Vias.PushViaHeader(new SIPViaHeader(trunkViaEP, CallProperties.CreateNewCallId()[..16]));

        // Display name: MicroSIP 抓包使用 "+862356767450@cq.ctcims.cn" 格式
        // From 域名使用 ClientUri 的 Host (IMS 域), 与 REGISTER 一致
        var clientUriHost = trunk.ClientUri != null
            ? SIPURI.ParseSIPURI(trunk.ClientUri.StartsWith("sip:") ? trunk.ClientUri : $"sip:{trunk.ClientUri}").HostAddress
            : trunkRegistrarUri.HostAddress;
        var displayName = $"{trunkNumber}@{clientUriHost}";

        trunkInvite.Header.From = new SIPFromHeader(displayName,
            new SIPURI(trunkNumber, localIP, null, SIPSchemesEnum.sip),
            CallProperties.CreateNewCallId()[..8]);
        trunkInvite.Header.To = new SIPToHeader(null,
            new SIPURI(outboundNumber, trunkRegistrarUri.Host, null, SIPSchemesEnum.sip), null);
        trunkInvite.Header.CallId = CallProperties.CreateNewCallId();
        trunkInvite.Header.CSeq = 1;
        trunkInvite.Header.MaxForwards = 70;

        // Contact: MicroSIP 抓包使用本地 IP + 端口 (192.168.40.140:54625;ob)
        var contactUri = new SIPURI(trunkNumber, $"{localIP}:{trunkTransportEP.Port}", null, SIPSchemesEnum.sip);
        contactUri.Parameters.Set("ob", null);
        trunkInvite.Header.Contact = [new SIPContactHeader(displayName, contactUri)];

        // Route: 强制下一跳为运营商 SIP 代理 (无 :5060 端口, 与 REGISTER 一致)
        var routeUri = SIPURI.ParseSIPURI($"sip:{trunkRegistrarUri.HostAddress}");
        trunkInvite.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

        // 复制 SDP (替换内网 IP 为 OutboundAddress)
        if (!string.IsNullOrEmpty(request.Body))
        {
            var sdpBody = request.Body;
            if (!string.IsNullOrEmpty(trunkOutIp))
            {
                sdpBody = System.Text.RegularExpressions.Regex.Replace(
                    sdpBody,
                    @"(c=IN IP4 )(\d+\.\d+\.\d+\.\d+)",
                    $"${{1}}{trunkOutIp}",
                    System.Text.RegularExpressions.RegexOptions.Multiline);
                sdpBody = System.Text.RegularExpressions.Regex.Replace(
                    sdpBody,
                    @"(o=.+IN IP4 )(\d+\.\d+\.\d+\.\d+)",
                    $"${{1}}{trunkOutIp}",
                    System.Text.RegularExpressions.RegexOptions.Multiline);
            }

            trunkInvite.Body = sdpBody;
            trunkInvite.Header.ContentType = request.Header.ContentType;
            trunkInvite.Header.ContentLength = sdpBody.Length;
        }

        try
        {
            // 使用 Trunk 专用传输层发送 INVITE (避开路由器 5060 端口转发回环)
            _logger.LogInformation("外呼 INVITE 报文:\n{Packet}", trunkInvite.ToString());
            await _trunkManager.SendRequestAsync(trunkEP, trunkInvite);
            _callManager.RegisterCalleeLeg(session, trunkInvite, trunkEP);
            _logger.LogInformation("外呼 INVITE 已发送到 Trunk {TrunkName} ({EP})", trunk.Name, trunkEP);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "外呼 INVITE 发送失败 (Trunk={TrunkName})", trunk.Name);
            await SendResponse(request, SIPResponseStatusCodesEnum.ServiceUnavailable, "Trunk unreachable", callerEP);
            _callManager.RemoveSession(session);
        }
    }

    /// <summary>
    /// 处理外呼 INVITE 的 401 挑战: 重新发送带 Digest 认证的 INVITE
    /// 运营商可能要求外呼 INVITE 也做 Digest 认证 (和 REGISTER 一样)
    /// </summary>
    private async Task HandleOutboundInviteAuthChallenge(
        CallSession session, SIPResponse challengeResponse, SIPEndPoint trunkEP)
    {
        var trunk = _options.Trunks.FirstOrDefault(t => t.Name == session.TrunkName && t.Enabled);
        if (trunk == null)
        {
            _logger.LogError("外呼 INVITE 401: 找不到 Trunk 配置 {Name}", session.TrunkName);
            return;
        }

        var authHeaders = challengeResponse.Header.AuthenticationHeaders;
        if (authHeaders == null || authHeaders.Count == 0)
        {
            _logger.LogWarning("外呼 INVITE 401: 无 WWW-Authenticate 头");
            return;
        }

        var authDigestRaw = authHeaders[0].SIPDigest;
        if (authDigestRaw == null)
        {
            _logger.LogWarning("外呼 INVITE 401: 无法解析 Digest");
            return;
        }

        _logger.LogInformation("外呼 INVITE 401 Digest: Realm={Realm}, Nonce={Nonce}, Qop={Qop}",
            authDigestRaw.Realm,
            authDigestRaw.Nonce?[..Math.Min(8, authDigestRaw.Nonce.Length)],
            authDigestRaw.Qop ?? "(null)");

        // 重新构建带认证的外呼 INVITE
        var trunkRegistrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
            ? trunk.Registrar : $"sip:{trunk.Registrar}");
        var trunkNumber = trunk.FromUser ?? trunk.Username.Split('@')[0];

        var (trunkOutIp, _) = _trunkManager.GetOutboundAddress(trunk);
        var trunkTransportEP = _trunkManager.GetTrunkTransportEP();

        // Via sent-by: 使用内网 IP + trunk 传输层端口
        var localIP = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                      && ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                      && !System.Net.IPAddress.IsLoopback(ua.Address)
                      && !ua.Address.Equals(System.Net.IPAddress.Any))
            .Select(ua => ua.Address.ToString())
            .FirstOrDefault() ?? "127.0.0.1";
        var trunkViaEP = new SIPEndPoint(SIPProtocolsEnum.udp,
            System.Net.IPAddress.Parse(localIP), trunkTransportEP.Port);

        // 外呼号码加 +86 前缀 (与 HandleOutboundInvite 一致)
        var outboundNumber = session.CalleeNumber;
        if (!outboundNumber.StartsWith("+") && outboundNumber.Length >= 5)
            outboundNumber = "+86" + outboundNumber;

        var calleeRequestUri = new SIPURI(outboundNumber, trunkOutIp, null, SIPSchemesEnum.sip);
        var reinvite = SIPRequest.GetRequest(SIPMethodsEnum.INVITE, calleeRequestUri);
        reinvite.URI = SIPURI.ParseSIPURI($"tel:{outboundNumber}");

        // 清除默认 Via, 替换为内网 IP + trunk 传输层端口
        reinvite.Header.Vias.Via.Clear();
        reinvite.Header.Vias.PushViaHeader(new SIPViaHeader(trunkViaEP, CallProperties.CreateNewCallId()[..16]));

        // Display name: 与 HandleOutboundInvite 一致, 使用 ClientUri Host (IMS 域)
        var clientUriHost = trunk.ClientUri != null
            ? SIPURI.ParseSIPURI(trunk.ClientUri.StartsWith("sip:") ? trunk.ClientUri : $"sip:{trunk.ClientUri}").HostAddress
            : trunkRegistrarUri.HostAddress;
        var displayName = $"{trunkNumber}@{clientUriHost}";

        reinvite.Header.From = new SIPFromHeader(displayName,
            new SIPURI(trunkNumber, localIP, null, SIPSchemesEnum.sip),
            CallProperties.CreateNewCallId()[..8]);
        reinvite.Header.To = new SIPToHeader(null,
            new SIPURI(outboundNumber, trunkRegistrarUri.Host, null, SIPSchemesEnum.sip), null);
        reinvite.Header.CallId = session.CalleeCallId; // 保持同一事务的 Call-ID
        reinvite.Header.CSeq = (session.CalleeInvite?.Header.CSeq ?? 0) + 1; // CSeq 递增
        reinvite.Header.MaxForwards = 70;

        // Contact: 使用本地 IP + 端口 (与 REGISTER 一致)
        var reinviteContactUri = new SIPURI(trunkNumber, $"{localIP}:{trunkTransportEP.Port}", null, SIPSchemesEnum.sip);
        reinviteContactUri.Parameters.Set("ob", null);
        reinvite.Header.Contact = [new SIPContactHeader(displayName, reinviteContactUri)];

        // Route: 无 :5060 端口 (与 REGISTER 一致)
        var routeUri = SIPURI.ParseSIPURI($"sip:{trunkRegistrarUri.HostAddress}");
        reinvite.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

        // Authorization URI: 使用 IMS 域 (sip:cq.ctcims.cn)
        var authDigestUri = $"sip:{clientUriHost}";
        var authDigest = _trunkManager.BuildManualDigest(
            trunk.Username, trunk.Password,
            !string.IsNullOrEmpty(trunk.Realm) ? trunk.Realm : authDigestRaw.Realm ?? "",
            authDigestRaw.Nonce ?? "", authDigestRaw.Qop ?? "auth",
            authDigestRaw.URI ?? authDigestUri,
            SIPMethodsEnum.INVITE.ToString(),
            authDigestRaw.Opaque ?? "");

        var authHeader = new SIPAuthenticationHeader(authDigest);
        reinvite.Header.AuthenticationHeaders.Add(authHeader);

        // 复制 SDP (替换内网 IP 为 OutboundAddress)
        if (session.CallerInvite != null && !string.IsNullOrEmpty(session.CallerInvite.Body))
        {
            var sdpBody = session.CallerInvite.Body;
            if (!string.IsNullOrEmpty(trunkOutIp))
            {
                sdpBody = System.Text.RegularExpressions.Regex.Replace(
                    sdpBody,
                    @"(c=IN IP4 )(\d+\.\d+\.\d+\.\d+)",
                    $"${{1}}{trunkOutIp}",
                    System.Text.RegularExpressions.RegexOptions.Multiline);
                sdpBody = System.Text.RegularExpressions.Regex.Replace(
                    sdpBody,
                    @"(o=.+IN IP4 )(\d+\.\d+\.\d+\.\d+)",
                    $"${{1}}{trunkOutIp}",
                    System.Text.RegularExpressions.RegexOptions.Multiline);
            }
            reinvite.Body = sdpBody;
            reinvite.Header.ContentType = session.CallerInvite.Header.ContentType;
            reinvite.Header.ContentLength = sdpBody.Length;
        }

        try
        {
            _logger.LogInformation("外呼 INVITE (带认证) 报文:\n{Packet}", reinvite.ToString());
            await _trunkManager.SendRequestAsync(trunkEP, reinvite);
            _callManager.RegisterCalleeLeg(session, reinvite, trunkEP);
            _logger.LogInformation("外呼 INVITE (带认证) 已重发到 Trunk {TrunkName} ({EP})",
                trunk.Name, trunkEP);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "外呼 INVITE (带认证) 重发失败");
        }
    }

    /// <summary>
    /// 处理运营商发来的 re-INVITE (in-dialog INVITE)
    /// 运营商在通话建立后可能发 re-INVITE 来修改会话参数 (如更新 SDP)
    /// 简单处理: 回 200 OK + 原始 SDP (保持原会话不变)
    /// 更完善的处理: 将 re-INVITE 转发给本地分机, 由分机决定是否接受
    /// </summary>
    private async Task HandleTrunkReInvite(SIPRequest reInvite, CallSession session, SIPEndPoint remoteEP)
    {
        _logger.LogInformation("处理 re-INVITE: CallId={CallId}, CSeq={CSeq}, 会话={SessionId}",
            reInvite.Header.CallId, reInvite.Header.CSeq, session.SessionId);

        // 回复 200 OK (带原会话的 SDP, 表示保持原会话参数)
        var okResponse = SIPResponse.GetResponse(reInvite, SIPResponseStatusCodesEnum.Ok, "OK");
        okResponse.Header.To.ToTag = reInvite.Header.To.ToTag; // 保留 To tag (in-dialog)

        // 如果有原会话的 SDP, 附带在 200 OK 中
        // 使用被叫侧 200 OK 中收到的 SDP (如果有的话)
        if (session.ForwardedCallerOkResponse != null && !string.IsNullOrEmpty(session.ForwardedCallerOkResponse.Body))
        {
            okResponse.Body = session.ForwardedCallerOkResponse.Body;
            okResponse.Header.ContentType = session.ForwardedCallerOkResponse.Header.ContentType;
            okResponse.Header.ContentLength = okResponse.Body.Length;
        }
        else if (!string.IsNullOrEmpty(reInvite.Body))
        {
            // 如果没有缓存 SDP, 但 re-INVITE 自带了 SDP, 也回带 SDP
            // 这是正常的 re-INVITE 场景: 对端提议新 SDP, 我们回带接受的 SDP
            okResponse.Body = reInvite.Body;
            okResponse.Header.ContentType = reInvite.Header.ContentType;
            okResponse.Header.ContentLength = okResponse.Body.Length;
        }

        // Contact 头: 使用运营商可达的地址
        if (session.IsOutboundTrunk)
        {
            // 外呼方向: Contact 使用 Trunk 的 OutboundAddress
            var trunk = _options.Trunks.FirstOrDefault(t => t.Name == session.TrunkName && t.Enabled);
            if (trunk != null)
            {
                var (outIp, outPort) = _trunkManager.GetOutboundAddress(trunk);
                var contactUri = new SIPURI(trunk.FromUser ?? trunk.Username.Split('@')[0],
                    $"{outIp}:{outPort}", null, SIPSchemesEnum.sip);
                contactUri.Parameters.Set("ob", null);
                okResponse.Header.Contact = [new SIPContactHeader(null, contactUri)];
            }
        }
        else
        {
            // 入站方向: Contact 使用公布地址
            var advEP = GetContactEPForClient(remoteEP);
            var contactUri = new SIPURI(SIPSchemesEnum.sip, advEP);
            okResponse.Header.Contact = [new SIPContactHeader(null, contactUri)];
        }

        // Supported 头 (避免运营商发 PRACK 等我们不支持的功能)
        okResponse.Header.Supported = "replaces, outbound";

        await _sipTransport!.SendResponseAsync(remoteEP, okResponse);
        _logger.LogInformation("re-INVITE 已回复 200 OK (保持原会话): CallId={CallId}", reInvite.Header.CallId);
    }

    /// <summary>
    /// 创建 B2BUA 被叫侧 INVITE 请求
    /// </summary>
    private SIPRequest CreateB2BUAInvite(SIPRequest originalInvite, RegisteredExtension callee, SIPEndPoint targetEP)
    {
        var callerNumber = originalInvite.Header.From.FromURI.User;

        // 尝试从 P-Asserted-Identity 提取更准确的主叫号码
        // 中国电信 IMS 入站 INVITE 的 From 头是 tel: 格式 (如 <tel:+8615320661625>)
        // 而 P-Asserted-Identity 包含标准格式的主叫号码 (如 <tel:15320661625>)
        // 本地 SIP 客户端 (Zoiper/DAG1000) 依赖 From 头显示来电号码
        string? paiNumber = null;
        if (originalInvite.Header.PassertedIdentity != null && originalInvite.Header.PassertedIdentity.Count > 0)
        {
            var paiUri = originalInvite.Header.PassertedIdentity[0].URI;
            if (paiUri != null)
                paiNumber = paiUri.User;
        }
        // 优先使用 PAI 号码 (更准确, 通常是去掉 +86 前缀的号码)
        var effectiveCallerNumber = paiNumber ?? callerNumber;

        // 新的 Request-URI 指向被叫的 Contact
        var requestUri = callee.ContactURI.CopyOf();

        // 创建新的 INVITE
        var invite = SIPRequest.GetRequest(SIPMethodsEnum.INVITE, requestUri);

        // From: 用主叫号但新 tag, 设置 display name 以便客户端显示来电号码
        var fromUri = new SIPURI(effectiveCallerNumber, targetEP.Address.ToString(), null, SIPSchemesEnum.sip);
        invite.Header.From = new SIPFromHeader(effectiveCallerNumber, fromUri, CallProperties.CreateNewCallId()[..8]);

        // To: 被叫号, 初始无 tag
        var toUri = new SIPURI(callee.Number, targetEP.Address.ToString(), null, SIPSchemesEnum.sip);
        invite.Header.To = new SIPToHeader(null, toUri, null);

        // CallId: 新的
        invite.Header.CallId = CallProperties.CreateNewCallId();

        // CSeq: 从 1 开始
        invite.Header.CSeq = 1;

        // Via: 公布地址
        invite.Header.Vias.PushViaHeader(new SIPViaHeader(targetEP, CallProperties.CreateNewCallId()[..16]));

        // Contact: 公布地址
        var serverContactUri = new SIPURI(SIPSchemesEnum.sip, targetEP);
        invite.Header.Contact = [new SIPContactHeader(null, serverContactUri)];

        // Record-Route: 强制被叫后续请求 (BYE 等) 路由到服务器
        var recordRouteUri = new SIPURI(SIPSchemesEnum.sip, targetEP);
        recordRouteUri.Parameters.Set("lr", null);
        invite.Header.RecordRoutes = new SIPRouteSet();
        invite.Header.RecordRoutes.PushRoute(new SIPRoute(recordRouteUri, true));

        // Max-Forwards
        invite.Header.MaxForwards = 70;

        // User-Agent
        invite.Header.UserAgent = "AsterTele/1.0";

        // Allow
        invite.Header.Allow = "INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER";

        // 复制 SDP
        if (!string.IsNullOrEmpty(originalInvite.Body))
        {
            invite.Body = originalInvite.Body;
            invite.Header.ContentType = originalInvite.Header.ContentType;
            invite.Header.ContentLength = originalInvite.Body.Length;
        }

        // Supported
        invite.Header.Supported = "replaces, outbound";

        // 透传 P-Asserted-Identity 头 (来电显示号码)
        // 中国电信 IMS 在入站 INVITE 中使用 PAI 头传递真实主叫号码
        // 本地 SIP 客户端 (Zoiper/DAG1000) 依赖此头显示来电号码
        if (originalInvite.Header.PassertedIdentity != null && originalInvite.Header.PassertedIdentity.Count > 0)
        {
            invite.Header.PassertedIdentity = originalInvite.Header.PassertedIdentity;
        }
        else if (!string.IsNullOrEmpty(effectiveCallerNumber))
        {
            // 无 PAI 头时, 用 From 头的号码构造 PAI (确保客户端能显示来电号码)
            var paiUri = new SIPURI(effectiveCallerNumber, targetEP.Address.ToString(), null, SIPSchemesEnum.sip);
            invite.Header.PassertedIdentity = [new SIPUriHeader(null, paiUri)];
        }

        return invite;
    }

    // ===== 被叫侧响应转发 (B2BUA 核心) =====

    private async Task ForwardCalleeResponse(SIPResponse response, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        try
        {
            // 通过被叫 Call-ID 查找对应的 B2BUA 会话
            var session = _callManager.FindByCalleeCallId(response.Header.CallId);
            if (session == null)
            {
                _logger.LogDebug("未找到 CallId={CallId} 对应的会话 (可能是非 B2BUA 响应)", response.Header.CallId);
                return;
            }

            // 根据主叫网络选择 Contact/Record-Route 地址
            var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);

            _logger.LogDebug("B2BUA 转发响应: {Status} 会话={SessionId}", response.Status, session.SessionId);

            switch (response.Status)
            {
                case SIPResponseStatusCodesEnum.Trying:
                    break;

                case SIPResponseStatusCodesEnum.Ringing:
                case SIPResponseStatusCodesEnum.SessionProgress:
                    session.State = CallState.Ringing;
                    var ringingResponse = SIPResponse.GetResponse(session.CallerInvite, response.Status, response.ReasonPhrase);
                    ringingResponse.Header.To.ToTag = session.B2buaToTag;
                    AddAdvertisedContact(ringingResponse, callerContactEP);
                    AddRecordRoute(ringingResponse, callerContactEP);
                    if (!string.IsNullOrEmpty(response.Body))
                    {
                        ringingResponse.Body = response.Body;
                        ringingResponse.Header.ContentType = response.Header.ContentType;
                        ringingResponse.Header.ContentLength = response.Body.Length;
                        // 183 Session Progress 带 SDP = 早期媒体 (early media)
                        // 客户端可以在振铃阶段就建立 RTP 接收提示音/忙音
                        if (response.Status == SIPResponseStatusCodesEnum.SessionProgress)
                            _logger.LogInformation("183 Session Progress 携带 SDP (早期媒体), 已修改为 RTP 中继地址: CallId={CallId}", session.CallerCallId);
                    }
                    _logger.LogInformation("转发 {Status} 给主叫: CallId={CallId}, SDP={HasSdp}",
                        response.Status, session.CallerCallId, !string.IsNullOrEmpty(response.Body));
                    await _sipTransport!.SendResponseAsync(session.CallerRemoteEP, ringingResponse);
                    break;

                case SIPResponseStatusCodesEnum.Ok:
                    if (session.Callee200OkProcessed)
                    {
                        session.Callee200OkRetransmitCount++;
                        _logger.LogDebug("被叫 200 OK 重传 #{Count}", session.Callee200OkRetransmitCount);

                        // 重传 200 OK 给主叫
                        if (session.ForwardedCallerOkResponse != null)
                            await _sipTransport!.SendResponseAsync(session.CallerRemoteEP, session.ForwardedCallerOkResponse);

                        // 200 OK 重传到达说明主叫的 ACK 没到服务器
                        // Proxy ACK 已在首次 200 OK 时发送, 这里只是继续重传 200 OK 给主叫
                        // 兜底: 超过 11 次重传 (~32s) 且 ACK 也没成功, 主动发 BYE 结束
                        if (session.Callee200OkRetransmitCount > 11 && !session.ByeProcessed)
                        {
                            _logger.LogWarning("被叫 200 OK 重传超限, 主动向被叫 {Callee} 发送 BYE", session.CalleeNumber);
                            session.ByeProcessed = true;
                            await SendByeToCallee(session);
                            _callManager.RemoveSession(session);
                        }
                        return;
                    }

                    // 首次 200 OK
                    session.Callee200OkProcessed = true;
                    session.CalleeToTag = response.Header.To.ToTag;

                    // 保存被叫侧 Contact URI (用于后续发 BYE)
                    var calleeContactHeader = response.Header.Contact.FirstOrDefault();
                    if (calleeContactHeader != null)
                        session.CalleeContactURI = calleeContactHeader.ContactURI.CopyOf();

                    // 更新被叫侧远端地址 (200 OK 的源地址比 INVITE 目标地址更准确, 可能因 NAT 不同)
                    session.CalleeRemoteEP = remoteEP.CopyOf();

                    // 取消无应答定时器 (被叫已接听)
                    session.NoAnswerCts?.Cancel();

                    _callManager.MarkConnected(session);

                    // 转发 200 OK 给主叫
                    // 关键: 保留原始 INVITE 的 Via (不替换!), 客户端用 Via branch 匹配 INVITE 事务
                    // 通过 Record-Route + Contact 让客户端把 ACK/BYE 路由到服务器
                    var okResponse = SIPResponse.GetResponse(session.CallerInvite, SIPResponseStatusCodesEnum.Ok, "OK");
                    okResponse.Header.To.ToTag = session.B2buaToTag;
                    AddAdvertisedContact(okResponse, callerContactEP);
                    AddRecordRoute(okResponse, callerContactEP);
                    if (!string.IsNullOrEmpty(response.Body))
                    {
                        okResponse.Body = response.Body;
                        okResponse.Header.ContentType = response.Header.ContentType;
                        okResponse.Header.ContentLength = response.Body.Length;
                    }
                    session.ForwardedCallerOkResponse = okResponse;
                    _logger.LogInformation("转发 200 OK 给主叫: CallId={CallId}", session.CallerCallId);
                    _logger.LogDebug("200 OK 详情: Contact={Contact}, ViaTop={Via}",
                        okResponse.Header.Contact.FirstOrDefault()?.ContactURI,
                        okResponse.Header.Vias.Via.FirstOrDefault());
                    await _sipTransport!.SendResponseAsync(session.CallerRemoteEP, okResponse);
                    _logger.LogInformation("通话建立: {Caller} <-> {Callee}", session.CallerNumber, session.CalleeNumber);

                    // 关键修复: 立即发送 Proxy ACK 给被叫
                    // 不等主叫的 ACK 到达 (可能因路由问题到不了), 直接代替主叫发 ACK 让被叫停止 200 OK 重传
                    // 如果主叫的真实 ACK 后续到达, HandleAck 会因 AckForwarded=true 而忽略
                    await SendProxyAckToCallee(session);
                    _logger.LogInformation("Proxy ACK 已随首次 200 OK 立即发送给被叫");

                    if (!string.IsNullOrEmpty(response.Body))
                        _logger.LogDebug("被叫 200 OK SDP:\n{Sdp}", response.Body);
                    break;

                case SIPResponseStatusCodesEnum.BusyHere:
                case SIPResponseStatusCodesEnum.Decline:
                    // B2BUA 代替主叫向被叫发 ACK for non-2xx (停止被叫重传)
                    await SendAckForNon2xxToCallee(session, response);

                    // 遇忙转移: 检查被叫是否有 Busy 转移规则
                    var busyForwardRule = _trunkManager.ResolveForwardRule(session.CalleeNumber, CallForwardType.Busy);
                    if (busyForwardRule != null && session.ForwardDepth < MaxForwardDepth)
                    {
                        _logger.LogInformation("遇忙转移: {From} → {To} (深度 {Depth})",
                            session.CalleeNumber, busyForwardRule.Target, session.ForwardDepth + 1);
                        await InitiateForwardCall(session, busyForwardRule.Target);
                        return; // 不回忙给主叫, 继续等转移结果
                    }

                    var busyResponse = SIPResponse.GetResponse(session.CallerInvite, response.Status, response.ReasonPhrase);
                    busyResponse.Header.To.ToTag = session.B2buaToTag;
                    AddAdvertisedContact(busyResponse, callerContactEP);
                    _logger.LogInformation("转发 {Status} 给主叫: CallId={CallId}, 目标EP={EP}, 已接听={AlreadyOk}",
                        response.Status, session.CallerCallId, session.CallerRemoteEP, session.Callee200OkProcessed);
                    await _sipTransport!.SendResponseAsync(session.CallerRemoteEP, busyResponse);
                    _callManager.RemoveSession(session);
                    break;

                default:
                    if (response.Status >= SIPResponseStatusCodesEnum.BadRequest)
                    {
                        // B2BUA 代替主叫向被叫发 ACK for non-2xx (停止被叫重传)
                        await SendAckForNon2xxToCallee(session, response);

                        var errResponse = SIPResponse.GetResponse(session.CallerInvite, response.Status, response.ReasonPhrase);
                        errResponse.Header.To.ToTag = session.B2buaToTag;
                        AddAdvertisedContact(errResponse, callerContactEP);
                        await _sipTransport!.SendResponseAsync(session.CallerRemoteEP, errResponse);
                        _callManager.RemoveSession(session);
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "转发被叫响应异常");
        }
    }

    /// <summary>
    /// 在转发给主叫的响应中添加 Record-Route 头 (指向公布地址)
    /// 确保 ACK / BYE / re-INVITE 等后续请求路由到服务器
    /// </summary>
    private void AddRecordRoute(SIPResponse response, SIPEndPoint advEP)
    {
        var rrUri = new SIPURI(SIPSchemesEnum.sip, advEP);
        rrUri.Parameters.Set("lr", null);
        var route = new SIPRoute(rrUri, true);
        response.Header.RecordRoutes = new SIPRouteSet();
        response.Header.RecordRoutes.PushRoute(route);
    }

    /// <summary>
    /// 在转发响应中设置 Contact 头 (指向公布地址)
    /// </summary>
    private void AddAdvertisedContact(SIPResponse response, SIPEndPoint advEP)
    {
        var contactUri = new SIPURI(SIPSchemesEnum.sip, advEP);
        response.Header.Contact = [new SIPContactHeader(null, contactUri)];
    }

    // ===== ACK 处理 =====

    /// <summary>
    /// B2BUA 代替主叫向被叫发 ACK (proxy ACK)
    /// 在首次转发 200 OK 给主叫时立即调用, 让被叫停止重传
    /// </summary>
    private async Task SendProxyAckToCallee(CallSession session)
    {
        if (session.CalleeInvite == null) return;

        session.AckForwarded = true; // 标记已转发, 后续主叫的真实 ACK 到达时忽略

        var calleeContactEP = GetContactEPForClient(session.CalleeRemoteEP);

        var ackRequest = SIPRequest.GetRequest(SIPMethodsEnum.ACK, session.CalleeInvite.URI.CopyOf());
        ackRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        ackRequest.Header.From = session.CalleeInvite.Header.From;
        ackRequest.Header.To = session.CalleeInvite.Header.To;
        if (session.CalleeToTag != null && string.IsNullOrEmpty(ackRequest.Header.To.ToTag))
            ackRequest.Header.To.ToTag = session.CalleeToTag;
        ackRequest.Header.CSeq = session.CalleeInvite.Header.CSeq;
        ackRequest.Header.Vias.PushViaHeader(new SIPViaHeader(calleeContactEP, CallProperties.CreateNewCallId()[..16]));
        ackRequest.Header.MaxForwards = 70;

        await _sipTransport!.SendRequestAsync(session.CalleeRemoteEP, ackRequest);
        _logger.LogInformation("Proxy ACK 已发送给被叫: {Callee} (代替主叫)", session.CalleeNumber);
    }

    private async Task HandleAck(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        _logger.LogInformation("ACK: CallId={CallId} 从={Remote} URI={URI}", request.Header.CallId, remoteEP, request.URI);

        // 查找主叫侧会话
        var session = _callManager.FindByCallerCallId(request.Header.CallId);
        if (session == null)
        {
            // 可能是 CANCEL 后 487 的 ACK (会话已移除), 静默忽略
            _logger.LogDebug("ACK 未找到对应会话 (可能是 487 ACK): CallId={CallId}", request.Header.CallId);
            return;
        }

        if (session.CalleeInvite == null)
        {
            _logger.LogWarning("ACK 会话无被叫 INVITE: CallId={CallId}", request.Header.CallId);
            return;
        }

        // 如果 ACK 已经转发过了 (重复 ACK)，忽略
        if (session.AckForwarded)
        {
            _logger.LogDebug("ACK 重复到达，忽略");
            return;
        }
        session.AckForwarded = true;

        // 创建向被叫侧的 ACK
        var ackRequest = SIPRequest.GetRequest(SIPMethodsEnum.ACK, session.CalleeInvite.URI.CopyOf());
        ackRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        ackRequest.Header.From = session.CalleeInvite.Header.From;
        ackRequest.Header.To = session.CalleeInvite.Header.To;
        if (session.CalleeToTag != null && string.IsNullOrEmpty(ackRequest.Header.To.ToTag))
            ackRequest.Header.To.ToTag = session.CalleeToTag;
        ackRequest.Header.CSeq = session.CalleeInvite.Header.CSeq;
        ackRequest.Header.Vias.PushViaHeader(new SIPViaHeader(GetContactEPForClient(session.CalleeRemoteEP), CallProperties.CreateNewCallId()[..16]));
        ackRequest.Header.MaxForwards = 70;

        // 透传 ACK 的 SDP (如果有的话，某些客户端在 ACK 中带 SDP)
        if (!string.IsNullOrEmpty(request.Body))
        {
            ackRequest.Body = request.Body;
            ackRequest.Header.ContentType = request.Header.ContentType;
            ackRequest.Header.ContentLength = request.Body.Length;
            _logger.LogDebug("ACK 带 SDP:\n{Sdp}", request.Body);
        }

        await _sipTransport!.SendRequestAsync(session.CalleeRemoteEP, ackRequest);
        _logger.LogInformation("ACK 已转发给被叫: {Callee} EP={EP}", session.CalleeNumber, session.CalleeRemoteEP);
    }

    // ===== BYE 处理 =====

    /// <summary>
    /// 处理 BYE 的 200 OK 响应 (对端确认已收到我们转发的 BYE)
    /// 收到后标记对端已挂断, 停止重传, 若双方都挂断则立即清理
    /// </summary>
    private Task HandleBye200Ok(SIPResponse response)
    {
        var callId = response.Header.CallId;

        // 查找是哪个会话的 BYE
        var session = _callManager.FindByCallerCallId(callId)
                      ?? _callManager.FindByCalleeCallId(callId);

        if (session == null)
        {
            _logger.LogDebug("BYE 200 OK 未找到对应会话: CallId={CallId}", callId);
            return Task.CompletedTask;
        }

        // 判断这个 200 OK 是对哪一侧 BYE 的响应
        bool isCallerCallId = (callId == session.CallerCallId);
        if (isCallerCallId)
        {
            // 主叫侧确认收到 BYE → 标记主叫已挂断
            if (!session.CallerHungUp)
            {
                session.CallerHungUp = true;
                _logger.LogInformation("主叫 {Caller} 确认挂断 (BYE 200 OK)", session.CallerNumber);
            }
        }
        else
        {
            // 被叫侧确认收到 BYE → 标记被叫已挂断
            if (!session.CalleeHungUp)
            {
                session.CalleeHungUp = true;
                _logger.LogInformation("被叫 {Callee} 确认挂断 (BYE 200 OK)", session.CalleeNumber);
            }
        }

        // 标记 BYE 已确认, 停止重传
        session.Bye200OkReceived = true;

        // 双方都挂断 → 立即清理
        if (session.CallerHungUp && session.CalleeHungUp)
        {
            _logger.LogInformation("双方均已挂断, 清理会话: {Caller} <-> {Callee}",
                session.CallerNumber, session.CalleeNumber);
            _callManager.RemoveSession(session);
        }

        return Task.CompletedTask;
    }

    private async Task HandleBye(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        _logger.LogInformation("BYE: CallId={CallId} 从 {Remote}", request.Header.CallId, remoteEP);

        // 尝试从主叫侧查找
        var session = _callManager.FindByCallerCallId(request.Header.CallId);
        bool isFromCaller = true;
        if (session == null)
        {
            // 尝试从被叫侧查找
            session = _callManager.FindByCalleeCallId(request.Header.CallId);
            isFromCaller = false;
        }

        if (session == null)
        {
            _logger.LogWarning("未找到 BYE 对应的会话: CallId={CallId}", request.Header.CallId);
            await SendResponse(request, SIPResponseStatusCodesEnum.CallLegTransactionDoesNotExist, "Call not found", remoteEP);
            return;
        }

        // 提取原始 BYE 的 Reason 头 (RFC 3326)
        // 运营商可能在 BYE 中携带 Reason 头说明挂断原因 (如 User Busy, Normal Clearing)
        var reasonHeader = request.Header.Reason;
        if (!string.IsNullOrEmpty(reasonHeader))
            _logger.LogInformation("BYE 携带 Reason 头: {Reason}", reasonHeader);
        else
            _logger.LogDebug("BYE 未携带 Reason 头");

        // 200 OK 给发送 BYE 的一方 (先回复, 即使已处理过也回 200 OK 吸收重传)
        await SendResponse(request, SIPResponseStatusCodesEnum.Ok, "OK", remoteEP);

        // 判断 BYE 来自哪一侧 (用第一次查找的结果, 因为后续可能因同时挂断改变)
        isFromCaller = (request.Header.CallId == session.CallerCallId);

        // 标记该侧已挂断
        if (isFromCaller)
        {
            if (session.CallerHungUp)
            {
                _logger.LogDebug("主叫侧 BYE 重传，已处理过");
                return;
            }
            session.CallerHungUp = true;
            _logger.LogInformation("主叫 {Caller} 已挂断", session.CallerNumber);
        }
        else
        {
            if (session.CalleeHungUp)
            {
                _logger.LogDebug("被叫侧 BYE 重传，已处理过");
                return;
            }
            session.CalleeHungUp = true;
            _logger.LogInformation("被叫 {Callee} 已挂断", session.CalleeNumber);
        }

        // 通话时长统计 (用于日志和短通话检测)
        var callDuration = session.ConnectedAt.HasValue
            ? (DateTime.UtcNow - session.ConnectedAt.Value).TotalSeconds
            : 0;
        _logger.LogInformation("通话时长: {Duration:F1}s (接通时间: {ConnectedAt})",
            callDuration, session.ConnectedAt?.ToString("HH:mm:ss.fff") ?? "N/A");

        // 向另一侧转发 BYE (仅当另一侧尚未挂断时)
        // 透传原始 BYE 的 Reason 头 (RFC 3326), 让对端知道挂断原因
        if (isFromCaller && !session.CalleeHungUp && session.CalleeInvite != null)
        {
            // 主叫挂断，向被叫发 BYE
            session.ByeTargetIsCallee = true;
            _logger.LogInformation("BYE 转发: 主叫 {Caller} 挂断 → 向被叫 {Callee} 发 BYE (EP={EP})",
                session.CallerNumber, session.CalleeNumber, session.CalleeRemoteEP);
            await SendByeToCallee(session, reasonHeader);
            session.ByeSentAt = DateTime.UtcNow;
        }
        else if (!isFromCaller && !session.CallerHungUp && session.CallerInvite != null)
        {
            // 被叫挂断，向主叫发 BYE
            session.ByeTargetIsCallee = false;
            _logger.LogInformation("BYE 转发: 被叫 {Callee} 挂断 → 向主叫 {Caller} 发 BYE (EP={EP})",
                session.CalleeNumber, session.CallerNumber, session.CallerRemoteEP);
            await SendByeToCaller(session, reasonHeader);
            session.ByeSentAt = DateTime.UtcNow;
        }

        // 双方都挂断了 → 立即清理会话
        if (session.CallerHungUp && session.CalleeHungUp)
        {
            _logger.LogInformation("双方均已挂断, 立即清理会话: {Caller} <-> {Callee}",
                session.CallerNumber, session.CalleeNumber);
            _callManager.RemoveSession(session);
            return;
        }

        // 只有一方挂断 → 进入 Disconnecting 等待另一方
        if (session.State != CallState.Disconnecting)
        {
            session.State = CallState.Disconnecting;
            session.ByeProcessed = true;
            _logger.LogInformation("通话等待对端挂断: {Caller} <-> {Callee} (已挂断: {HungSide})",
                session.CallerNumber, session.CalleeNumber,
                session.CallerHungUp ? session.CallerNumber : session.CalleeNumber);
        }
    }

    private async Task SendByeToCallee(CallSession session, string? reason = null)
    {
        if (session.CalleeInvite == null) return;

        // 确定被叫侧 Contact EP (用于 Via/Contact 头)
        var calleeContactEP = GetContactEPForClient(session.CalleeRemoteEP);

        // 确定 BYE Request-URI
        SIPURI byeRequestUri;
        if (session.IsOutboundTrunk)
        {
            // 外呼方向: 被叫侧是运营商
            // BYE Request-URI 使用运营商 200 OK Contact (已缓存在 session.CalleeContactURI)
            if (session.CalleeContactURI != null)
            {
                byeRequestUri = session.CalleeContactURI.CopyOf();
                _logger.LogInformation("外呼 BYE Request-URI 使用运营商 Contact: {URI}", byeRequestUri);
            }
            else
            {
                // fallback: 使用运营商的源 IP
                byeRequestUri = new SIPURI(session.CalleeNumber,
                    session.CalleeRemoteEP.Address.ToString(), null, SIPSchemesEnum.sip);
                _logger.LogWarning("无运营商 Contact, BYE Request-URI 使用源地址: {URI}", byeRequestUri);
            }
        }
        else
        {
            // 本地被叫: 优先使用 200 OK 中的 Contact URI (比注册 Contact 更权威, 可能因 NAT 不同)
            if (session.CalleeContactURI != null)
            {
                byeRequestUri = session.CalleeContactURI.CopyOf();
                _logger.LogDebug("BYE Request-URI 使用被叫 200 OK Contact: {URI}", byeRequestUri);
            }
            else
            {
                byeRequestUri = session.CalleeInvite.URI.CopyOf();
            }
        }

        var byeRequest = SIPRequest.GetRequest(SIPMethodsEnum.BYE, byeRequestUri);
        byeRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        byeRequest.Header.From = session.CalleeInvite.Header.From;

        var toUri = new SIPURI(session.CalleeNumber, calleeContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
        byeRequest.Header.To = new SIPToHeader(null, toUri, session.CalleeToTag);
        byeRequest.Header.CSeq = session.CalleeInvite.Header.CSeq + 1;
        byeRequest.Header.Vias.PushViaHeader(new SIPViaHeader(calleeContactEP, CallProperties.CreateNewCallId()[..16]));
        byeRequest.Header.MaxForwards = 70;
        var contactUri = new SIPURI(SIPSchemesEnum.sip, calleeContactEP);
        byeRequest.Header.Contact = [new SIPContactHeader(null, contactUri)];

        // Reason 头: 透传原始 BYE 的 Reason (RFC 3326)
        // 让对端知道挂断原因 (如 User Busy, Normal Clearing 等)
        if (!string.IsNullOrEmpty(reason))
        {
            byeRequest.Header.Reason = reason;
            _logger.LogInformation("BYE 携带 Reason 头: {Reason}", reason);
        }

        // Route: 如果 INVITE 有 Record-Route, BYE 也需要 Route 头 (按 RFC 3261 顺序)
        var calleeRecordRoutes = session.CalleeInvite.Header.RecordRoutes;
        if (calleeRecordRoutes != null && calleeRecordRoutes.Length > 0)
        {
            var reversed = calleeRecordRoutes.Reversed();
            for (int i = 0; i < reversed.Length; i++)
            {
                byeRequest.Header.Routes.PushRoute(reversed.GetAt(i));
            }
        }

        await _sipTransport!.SendRequestAsync(session.CalleeRemoteEP, byeRequest);
        _logger.LogInformation("BYE 已发送给被叫: {Callee} EP={EP}", session.CalleeNumber, session.CalleeRemoteEP);
    }

    private async Task SendByeToCaller(CallSession session, string? reason = null)
    {
        if (session.CallerInvite == null) return;

        var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);

        // 确定 BYE Request-URI
        SIPURI byeRequestUri;
        if (!session.IsOutboundTrunk)
        {
            // 入站方向: 主叫侧是运营商
            // BYE Request-URI 使用运营商 INVITE 的 Contact (已缓存在 session.CallerContactURI)
            if (session.CallerContactURI != null)
            {
                byeRequestUri = session.CallerContactURI.CopyOf();
                _logger.LogInformation("入站 BYE Request-URI 使用运营商 Contact: {URI}", byeRequestUri);
            }
            else
            {
                // fallback: 用运营商的源 IP
                byeRequestUri = new SIPURI(session.CallerNumber,
                    session.CallerRemoteEP.Address.ToString(), null, SIPSchemesEnum.sip);
                _logger.LogWarning("无运营商 Contact, BYE Request-URI 使用源地址: {URI}", byeRequestUri);
            }
        }
        else
        {
            // 外呼方向: 主叫侧是本地分机
            // BYE Request-URI 应使用分机的 Contact URI (而非 INVITE 的 Request-URI, 那是被叫号码)
            if (session.CallerContactURI != null)
            {
                byeRequestUri = session.CallerContactURI.CopyOf();
                _logger.LogInformation("外呼 BYE Request-URI 使用本地分机 Contact: {URI}", byeRequestUri);
            }
            else
            {
                // fallback: 构造分机 Contact URI
                byeRequestUri = new SIPURI(session.CallerNumber,
                    session.CallerRemoteEP.Address.ToString(), null, SIPSchemesEnum.sip);
                _logger.LogWarning("无主叫 Contact URI, BYE Request-URI 使用构造地址: {URI}", byeRequestUri);
            }
        }

        var byeRequest = SIPRequest.GetRequest(SIPMethodsEnum.BYE, byeRequestUri);
        byeRequest.Header.CallId = session.CallerInvite.Header.CallId;

        // 设置 From/To
        if (!session.IsOutboundTrunk && _options.Trunks.Any(t => t.Enabled))
        {
            // 入站方向: 我们是被叫侧, BYE 从我们发给运营商
            // From: 我们的身份 (To of original INVITE + our tag)
            // To: 运营商的身份 (From of original INVITE + their tag)
            byeRequest.Header.From = new SIPFromHeader(null,
                session.CallerInvite.Header.To.ToURI.CopyOf(), session.B2buaToTag);
            byeRequest.Header.To = new SIPToHeader(null,
                session.CallerInvite.Header.From.FromURI.CopyOf(), session.CallerFromTag);
        }
        else
        {
            // 外呼/本地方向
            var fromUri = new SIPURI(session.CalleeNumber, callerContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
            byeRequest.Header.From = new SIPFromHeader(null, fromUri, session.B2buaToTag);
            var toUri = new SIPURI(session.CallerNumber, callerContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
            byeRequest.Header.To = new SIPToHeader(null, toUri, session.CallerFromTag);
        }

        byeRequest.Header.CSeq = session.CallerInvite.Header.CSeq + 1;
        byeRequest.Header.Vias.PushViaHeader(new SIPViaHeader(callerContactEP, CallProperties.CreateNewCallId()[..16]));
        byeRequest.Header.MaxForwards = 70;
        var contactUri = new SIPURI(SIPSchemesEnum.sip, callerContactEP);
        byeRequest.Header.Contact = [new SIPContactHeader(null, contactUri)];

        // Reason 头: 透传原始 BYE 的 Reason (RFC 3326)
        // 让对端知道挂断原因 (如 User Busy, Normal Clearing 等)
        if (!string.IsNullOrEmpty(reason))
        {
            byeRequest.Header.Reason = reason;
            _logger.LogInformation("BYE 携带 Reason 头: {Reason}", reason);
        }

        // Route: 如果运营商 INVITE 有 Record-Route, BYE 也需要 Route 头
        var callerRecordRoutes = session.CallerInvite.Header.RecordRoutes;
        if (callerRecordRoutes != null && callerRecordRoutes.Length > 0)
        {
            var reversed = callerRecordRoutes.Reversed();
            for (int i = 0; i < reversed.Length; i++)
            {
                byeRequest.Header.Routes.PushRoute(reversed.GetAt(i));
            }
        }

        await _sipTransport!.SendRequestAsync(session.CallerRemoteEP, byeRequest);
        _logger.LogInformation("BYE 已发送给主叫: {Caller} EP={EP}", session.CallerNumber, session.CallerRemoteEP);
    }

    // ===== CANCEL 处理 =====

    private async Task HandleCancel(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        _logger.LogInformation("CANCEL: CallId={CallId}", request.Header.CallId);

        var session = _callManager.FindByCallerCallId(request.Header.CallId);
        if (session == null)
        {
            await SendResponse(request, SIPResponseStatusCodesEnum.CallLegTransactionDoesNotExist, "Call not found", remoteEP);
            return;
        }

        var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);

        // 200 OK 给 CANCEL 发送者
        await SendResponse(request, SIPResponseStatusCodesEnum.Ok, "OK", remoteEP);

        // 向被叫发送 CANCEL
        if (session.CalleeInvite != null)
        {
            var cancelRequest = SIPRequest.GetRequest(SIPMethodsEnum.CANCEL, session.CalleeInvite.URI.CopyOf());
            cancelRequest.Header.CallId = session.CalleeInvite.Header.CallId;
            cancelRequest.Header.From = session.CalleeInvite.Header.From;
            cancelRequest.Header.To = session.CalleeInvite.Header.To;
            cancelRequest.Header.CSeq = session.CalleeInvite.Header.CSeq;
            cancelRequest.Header.Vias = new SIPViaSet { Via = new List<SIPViaHeader>(session.CalleeInvite.Header.Vias.Via) };

            await _sipTransport!.SendRequestAsync(session.CalleeRemoteEP, cancelRequest);

            // 向主叫发送 487 Request Terminated (带 B2BUA To tag + Contact)
            var terminatedResponse = SIPResponse.GetResponse(session.CallerInvite,
                SIPResponseStatusCodesEnum.RequestTerminated, "Request Terminated");
            terminatedResponse.Header.To.ToTag = session.B2buaToTag;
            AddAdvertisedContact(terminatedResponse, callerContactEP);
            await _sipTransport.SendResponseAsync(session.CallerRemoteEP, terminatedResponse);
        }

        _callManager.RemoveSession(session);
        _logger.LogInformation("呼叫已取消: {Caller} -> {Callee}", session.CallerNumber, session.CalleeNumber);
    }

    // ===== OPTIONS 处理 =====

    private async Task HandleOptions(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        _logger.LogDebug("OPTIONS: 从 {Remote}", remoteEP);
        await SendResponse(request, SIPResponseStatusCodesEnum.Ok, "OK", remoteEP);
    }

    /// <summary>
    /// 处理 SIP INFO 请求 (用于 DTMF 信令)
    /// 支持两种 DTMF 格式: application/dtmf-relay 和 application/dtmf
    /// </summary>
    private async Task HandleInfo(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        _logger.LogDebug("INFO: 从 {Remote}, Content-Type={ContentType}", remoteEP, request.Header.ContentType);

        // 尝试解析 DTMF
        string? dtmfDigit = null;

        if (!string.IsNullOrEmpty(request.Body))
        {
            if (request.Header.ContentType?.Contains("dtmf-relay") == true)
            {
                // application/dtmf-relay: Signal=1\nDuration=160
                var match = System.Text.RegularExpressions.Regex.Match(request.Body, @"Signal\s*=\s*(\S)");
                if (match.Success)
                    dtmfDigit = match.Groups[1].Value;
            }
            else if (request.Header.ContentType?.Contains("dtmf") == true)
            {
                // application/dtmf: 直接是数字
                dtmfDigit = request.Body.Trim();
            }
        }

        if (dtmfDigit != null)
        {
            _logger.LogInformation("DTMF 收到: digit={Digit} (来源: {Remote})", dtmfDigit, remoteEP);
            // TODO: 将 DTMF 转发给 IVR 会话管理器, 收集完整分机号后发起转接
            // 当前 IVR 骨架阶段仅记录日志
        }

        // 回 200 OK
        await SendResponse(request, SIPResponseStatusCodesEnum.Ok, "OK", remoteEP);
    }

    // ===== 会话清理 =====

    /// <summary>
    /// 清理卡住的幽灵会话 + BYE 超时重传和强制清理
    /// - Initiating/Ringing 超 90 秒: 清理
    /// - Connected 超 2 小时: 清理
    /// - Disconnecting: BYE 重传 (5s 间隔, 最多 3 次), 超 20 秒强制清理
    /// - 双方都已挂断: 立即清理
    /// </summary>
    private void CleanupStaleSessions()
    {
        var now = DateTime.UtcNow;
        foreach (var session in _callManager.GetActiveSessions())
        {
            var age = now - session.CreatedAt;

            // 双方都已挂断 → 立即清理 (理论上 HandleBye/HandleBye200Ok 已处理, 这里是兜底)
            if (session.CallerHungUp && session.CalleeHungUp)
            {
                _logger.LogInformation("清理: 双方均已挂断 {Caller} <-> {Callee}",
                    session.CallerNumber, session.CalleeNumber);
                _callManager.RemoveSession(session);
                continue;
            }

            // Disconnecting 状态: BYE 超时重传和强制清理
            if (session.State == CallState.Disconnecting && session.ByeSentAt.HasValue && !session.Bye200OkReceived)
            {
                var byeAge = now - session.ByeSentAt.Value;

                // BYE 重传: 每 5 秒重传一次, 最多 3 次
                if (byeAge > TimeSpan.FromSeconds(5 * (session.ByeRetransmitCount + 1)) &&
                    session.ByeRetransmitCount < 3)
                {
                    session.ByeRetransmitCount++;
                    _logger.LogWarning("BYE 超时未确认, 重传 #{Count} 给 {Target}",
                        session.ByeRetransmitCount,
                        session.ByeTargetIsCallee ? $"被叫({session.CalleeNumber})" : $"主叫({session.CallerNumber})");

                    // 异步重传 BYE
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            if (session.ByeTargetIsCallee)
                                await SendByeToCallee(session);
                            else
                                await SendByeToCaller(session);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "BYE 重传失败");
                        }
                    });
                }

                // 强制清理: BYE 发出超过 20 秒仍未确认
                if (byeAge > TimeSpan.FromSeconds(20))
                {
                    _logger.LogWarning("BYE 超时 20 秒未确认, 强制清理会话: {Session}", session);
                    _callManager.RemoveSession(session);
                }

                continue;
            }

            if ((session.State != CallState.Connected && age > TimeSpan.FromSeconds(90)) ||
                (session.State == CallState.Connected && age > TimeSpan.FromHours(2)))
            {
                _logger.LogWarning("清理幽灵会话: {Session}, 存活={Age}", session, age);
                _callManager.RemoveSession(session);
            }
        }
    }

    // ===== ACK for non-2xx =====

    /// <summary>
    /// B2BUA 代替主叫向被叫发 ACK for non-2xx (停止被叫重传 486/487 等)
    /// 在 stateless 模式下, UAS 事务引擎不会自动发 ACK for non-2xx, 必须手动处理
    /// </summary>
    private async Task SendAckForNon2xxToCallee(CallSession session, SIPResponse calleeResponse)
    {
        if (session.CalleeInvite == null) return;

        var calleeContactEP = GetContactEPForClient(session.CalleeRemoteEP);

        var ackRequest = SIPRequest.GetRequest(SIPMethodsEnum.ACK, session.CalleeInvite.URI.CopyOf());
        ackRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        ackRequest.Header.From = session.CalleeInvite.Header.From;
        ackRequest.Header.To = session.CalleeInvite.Header.To;
        // 复制响应中的 To tag (被叫已添加了自己的 tag)
        if (!string.IsNullOrEmpty(calleeResponse.Header.To.ToTag))
            ackRequest.Header.To.ToTag = calleeResponse.Header.To.ToTag;
        ackRequest.Header.CSeq = session.CalleeInvite.Header.CSeq; // CSeq 号与 INVITE 相同, method=ACK
        ackRequest.Header.Vias.PushViaHeader(new SIPViaHeader(calleeContactEP, CallProperties.CreateNewCallId()[..16]));
        ackRequest.Header.MaxForwards = 70;

        await _sipTransport!.SendRequestAsync(session.CalleeRemoteEP, ackRequest);
        _logger.LogInformation("ACK for non-2xx 已发送给被叫: {Callee} (status={Status})",
            session.CalleeNumber, calleeResponse.Status);
    }

    // ===== 网络路由智能选择 =====

    /// <summary>
    /// 判断两个 IP 是否在同一 /24 子网
    /// 同子网客户端可直接访问服务器 IP, 无需经路由器
    /// </summary>
    private bool IsSameSubnet(IPAddress a, IPAddress b)
    {
        var ab = a.GetAddressBytes();
        var bb = b.GetAddressBytes();
        if (ab.Length != bb.Length || ab.Length < 3) return false;
        return ab[0] == bb[0] && ab[1] == bb[1] && ab[2] == bb[2];
    }

    /// <summary>
    /// 根据客户端来源网络选择合适的 Contact 端点
    /// - 同子网客户端: 使用服务器直连 IP (ACK/BYE 直接到服务器, 不经路由器)
    /// - 跨子网客户端: 使用 AdvertisedAddress (经路由器端口转发)
    /// </summary>
    private SIPEndPoint GetContactEPForClient(SIPEndPoint clientEP)
    {
        if (_localEP != SIPEndPoint.Empty && IsSameSubnet(clientEP.Address, _localEP.Address))
        {
            _logger.LogDebug("客户端 {Client} 与服务器同子网, 使用直连地址 {Local}", clientEP.Address, _localEP.Address);
            return _localEP;
        }
        _logger.LogDebug("客户端 {Client} 跨子网, 使用 NAT 地址 {Adv}", clientEP.Address, _advertisedEP.Address);
        return _advertisedEP;
    }

    /// <summary>
    /// 判断请求是否来自 SIP Trunk 运营商网络
    /// 通过比对运营商 Registrar 域名解析后的 IP 列表来判断
    /// </summary>
    private bool IsFromTrunkNetwork(SIPEndPoint remoteEP)
    {
        foreach (var trunk in _options.Trunks.Where(t => t.Enabled))
        {
            var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
                ? trunk.Registrar : $"sip:{trunk.Registrar}");
            var trunkIP = DnsResolver.Resolve(registrarUri.HostAddress, _options.DnsServer, _logger);
            if (trunkIP != null && trunkIP.Equals(remoteEP.Address))
                return true;
        }
        return false;
    }

    // ===== 呼叫转移 =====

    /// <summary>
    /// 处理语音信箱转移 (骨架)
    /// 当前阶段: 记录日志 + 向主叫返回 486 Busy (因无 RTP 音频能力)
    /// 后续: 应答呼叫 → 播放提示音 → 录音 → 保存留言
    /// </summary>
    private async Task HandleVoiceMailForward(CallSession session)
    {
        var vmSession = new VoiceMailSession
        {
            MailboxExtension = session.CalleeNumber,
            CallerNumber = session.CallerNumber,
            State = VoiceMailState.WaitingForAnswer
        };

        _logger.LogInformation("语音信箱: 分机={Mailbox}, 主叫={Caller} (RTP 音频待实现)",
            vmSession.MailboxExtension, vmSession.CallerNumber);

        // TODO: 完整语音信箱流程 (需 RTP 音频 + NAudio)
        // 1. 应答呼叫 (200 OK + SDP)
        // 2. 播放提示音 ("{MailboxExtension} 暂时无法接听，请在滴声后留言")
        // 3. 录音 (RTP → WAV/MP3, 限制最长 60 秒)
        // 4. 保存留言文件到 voicemail/{extension}/{timestamp}.wav
        // 5. 通知分机有新留言 (MWI NOTIFY)

        // 骨架: 向主叫返回 480 Temporarily Unavailable + Reason 头
        var vmResp = SIPResponse.GetResponse(session.CallerInvite,
            SIPResponseStatusCodesEnum.TemporarilyUnavailable, "Voicemail not available yet");
        vmResp.Header.To.ToTag = session.B2buaToTag;
        var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);
        AddAdvertisedContact(vmResp, callerContactEP);
        await _sipTransport!.SendResponseAsync(session.CallerRemoteEP, vmResp);

        _logger.LogInformation("语音信箱骨架: 已返回 480 (分机={Mailbox}, 主叫={Caller})",
            vmSession.MailboxExtension, vmSession.CallerNumber);
        _callManager.RemoveSession(session);
    }

    /// <summary>
    /// 发起呼叫转移: 保留主叫侧会话, 替换被叫侧为转移目标
    /// 支持 Busy / NoAnswer 两种触发场景
    /// </summary>
    private async Task InitiateForwardCall(CallSession session, string targetNumber)
    {
        if (_sipTransport == null) return;

        // 清理旧的被叫腿
        if (session.CalleeCallId != null)
            _callManager.UnregisterCalleeLeg(session.CalleeCallId);

        // 取消无应答定时器
        session.NoAnswerCts?.Cancel();
        session.NoAnswerCts?.Dispose();
        session.NoAnswerCts = null;

        // 更新被叫号码和转移深度
        var originalCallee = session.CalleeNumber;
        session.CalleeNumber = targetNumber;
        session.ForwardDepth++;
        session.Callee200OkProcessed = false;
        session.Callee200OkRetransmitCount = 0;
        session.AckForwarded = false;
        session.AckSdpForwarded = false;

        _logger.LogInformation("呼叫转移执行: {From} → {To} (深度 {Depth})",
            originalCallee, targetNumber, session.ForwardDepth);

        // 语音信箱检测: 转移目标为 "voicemail" 时走语音信箱骨架
        if (targetNumber.Equals("voicemail", StringComparison.OrdinalIgnoreCase))
        {
            await HandleVoiceMailForward(session);
            return;
        }

        // 检查转移深度
        if (session.ForwardDepth > MaxForwardDepth)
        {
            _logger.LogWarning("转移深度超限 ({Depth}), 停止转移", session.ForwardDepth);
            var loopResp = SIPResponse.GetResponse(session.CallerInvite,
                SIPResponseStatusCodesEnum.LoopDetected, "Forward loop detected");
            loopResp.Header.To.ToTag = session.B2buaToTag;
            var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);
            AddAdvertisedContact(loopResp, callerContactEP);
            await _sipTransport.SendResponseAsync(session.CallerRemoteEP, loopResp);
            _callManager.RemoveSession(session);
            return;
        }

        // 检查转移目标的无条件转移 (解析转移链)
        var unconditionalRule = _trunkManager.ResolveForwardRule(targetNumber, CallForwardType.Unconditional);
        if (unconditionalRule != null)
        {
            _logger.LogInformation("转移目标 {Target} 又有无条件转移 → {Final}", targetNumber, unconditionalRule.Target);
            targetNumber = unconditionalRule.Target;
            session.CalleeNumber = targetNumber;
        }

        // 查找转移目标的注册信息
        var calleeReg = _registrationStore.GetRegistration(targetNumber);
        if (calleeReg == null)
        {
            _logger.LogWarning("转移目标分机 {Number} 未注册", targetNumber);
            var notFoundResp = SIPResponse.GetResponse(session.CallerInvite,
                SIPResponseStatusCodesEnum.NotFound, "Forward target not registered");
            notFoundResp.Header.To.ToTag = session.B2buaToTag;
            var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);
            AddAdvertisedContact(notFoundResp, callerContactEP);
            await _sipTransport.SendResponseAsync(session.CallerRemoteEP, notFoundResp);
            _callManager.RemoveSession(session);
            return;
        }

        // 重新发送 180 Ringing 给主叫 (表示正在转接中)
        var ringingResp = SIPResponse.GetResponse(session.CallerInvite,
            SIPResponseStatusCodesEnum.Ringing, "Ringing");
        ringingResp.Header.To.ToTag = session.B2buaToTag;
        var callerCEP = GetContactEPForClient(session.CallerRemoteEP);
        AddAdvertisedContact(ringingResp, callerCEP);
        AddRecordRoute(ringingResp, callerCEP);
        await _sipTransport.SendResponseAsync(session.CallerRemoteEP, ringingResp);

        // 创建新的 B2BUA INVITE 给转移目标
        var calleeTargetEP = GetContactEPForClient(new SIPEndPoint(SIPProtocolsEnum.udp,
            calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port));
        var calleeInvite = CreateB2BUAInvite(session.CallerInvite, calleeReg, calleeTargetEP);
        session.CalleeNumber = calleeReg.Number;

        try
        {
            var calleeEP = new SIPEndPoint(SIPProtocolsEnum.udp,
                calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port);
            _logger.LogInformation("向转移目标 {Number} ({Contact}) 发送 INVITE", calleeReg.Number, calleeReg.ContactURI);
            await _sipTransport.SendRequestAsync(calleeEP, calleeInvite);
            _callManager.RegisterCalleeLeg(session, calleeInvite, calleeEP);

            // 启动无应答定时器
            StartNoAnswerTimer(session);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "向转移目标 {Number} 发送 INVITE 失败", calleeReg.Number);
            var errResp = SIPResponse.GetResponse(session.CallerInvite,
                SIPResponseStatusCodesEnum.ServiceUnavailable, "Forward target unreachable");
            errResp.Header.To.ToTag = session.B2buaToTag;
            var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);
            AddAdvertisedContact(errResp, callerContactEP);
            await _sipTransport.SendResponseAsync(session.CallerRemoteEP, errResp);
            _callManager.RemoveSession(session);
        }
    }

    /// <summary>
    /// 启动无应答超时定时器
    /// 当被叫在配置的超时时间内未接听, 触发 NoAnswer 转移
    /// </summary>
    private void StartNoAnswerTimer(CallSession session)
    {
        // 取消已有定时器
        session.NoAnswerCts?.Cancel();
        session.NoAnswerCts?.Dispose();

        // 查找 NoAnswer 转移规则, 获取超时时间
        var noAnswerRule = _trunkManager.ResolveForwardRule(session.CalleeNumber, CallForwardType.NoAnswer);
        if (noAnswerRule == null) return; // 无 NoAnswer 规则则不启动定时器

        var timeoutSeconds = noAnswerRule.NoAnswerTimeout > 0 ? noAnswerRule.NoAnswerTimeout : 15;
        session.NoAnswerCts = new CancellationTokenSource();

        _logger.LogInformation("启动无应答定时器: 被叫={Callee}, 超时={Timeout}s, 转移目标={Target}",
            session.CalleeNumber, timeoutSeconds, noAnswerRule.Target);

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(timeoutSeconds * 1000, session.NoAnswerCts!.Token);

                // 超时到达, 检查会话是否仍未接听
                if (session.State == CallState.Ringing || session.State == CallState.Initiating)
                {
                    _logger.LogInformation("无应答超时: 被叫 {Callee} 未接, 转移到 {Target}",
                        session.CalleeNumber, noAnswerRule.Target);

                    // 向当前被叫发 CANCEL
                    if (session.CalleeInvite != null && !session.CalleeHungUp)
                    {
                        await SendCancelToCallee(session);
                    }

                    // 执行转移
                    await InitiateForwardCall(session, noAnswerRule.Target);
                }
            }
            catch (OperationCanceledException)
            {
                // 正常取消 (被叫已接听或会话已结束)
                _logger.LogDebug("无应答定时器已取消: 被叫={Callee}", session.CalleeNumber);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "无应答定时器异常");
            }
        }, session.NoAnswerCts!.Token);
    }

    /// <summary>
    /// 向被叫发送 CANCEL 请求 (用于无应答超时取消当前呼叫)
    /// </summary>
    private async Task SendCancelToCallee(CallSession session)
    {
        if (_sipTransport == null || session.CalleeInvite == null) return;

        var cancelRequest = SIPRequest.GetRequest(SIPMethodsEnum.CANCEL, session.CalleeInvite.URI);
        cancelRequest.Header.CallId = session.CalleeCallId;
        cancelRequest.Header.From = session.CalleeInvite.Header.From;
        cancelRequest.Header.To = session.CalleeInvite.Header.To;
        cancelRequest.Header.CSeq = session.CalleeInvite.Header.CSeq;
        cancelRequest.Header.Vias = session.CalleeInvite.Header.Vias;
        cancelRequest.Header.MaxForwards = 70;

        await _sipTransport.SendRequestAsync(session.CalleeRemoteEP, cancelRequest);
        _logger.LogInformation("CANCEL 已发送给被叫: {Callee}", session.CalleeNumber);
    }

    // ===== 工具方法 =====

    private async Task SendResponse(SIPRequest request, SIPResponseStatusCodesEnum status, string reason, SIPEndPoint remoteEP)
    {
        var response = SIPResponse.GetResponse(request, status, reason);
        await _sipTransport!.SendResponseAsync(remoteEP, response);
    }

    /// <summary>
    /// 将 SIPURI 解析为 SIPEndPoint (支持域名 + 自定义 DNS 服务器)
    /// </summary>
    private SIPEndPoint ResolveSipUriEndPoint(SIPURI uri)
    {
        var host = uri.HostAddress;
        var portStr = uri.HostPort;
        int port;

        if (string.IsNullOrEmpty(portStr))
        {
            port = uri.Protocol == SIPProtocolsEnum.tls ? 5061 : 5060;
        }
        else
        {
            port = int.TryParse(portStr, out var p) ? p : 5060;
        }

        var ip = DnsResolver.Resolve(host, _options.DnsServer, _logger);
        return new SIPEndPoint(SIPProtocolsEnum.udp, ip, port);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _cleanupTimer?.Dispose();
            _sipTransport?.Shutdown();
        }
    }
}
