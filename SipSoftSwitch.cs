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
    private readonly ILogger<SipSoftSwitch> _logger;
    private readonly SipOptions _options;
    private readonly RegistrationStore _registrationStore;
    private readonly CallManager _callManager;
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
        CallManager callManager)
    {
        _logger = logger;
        _options = options.Value;
        _registrationStore = registrationStore;
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

            // 处理 BYE 的 200 OK 响应 (服务端主动发出的 BYE 得到对端确认)
            if (sipResponse.Status == SIPResponseStatusCodesEnum.Ok &&
                sipResponse.Header.CSeqMethod == SIPMethodsEnum.BYE)
            {
                await HandleBye200Ok(sipResponse);
                return;
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
        // 从 To 头提取分机号
        var extensionNumber = request.Header.To.ToURI.User;
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

        _logger.LogInformation("INVITE: {Caller} -> {Callee}", callerNumber, calleeNumber);
        _logger.LogDebug("INVITE SDP:\n{Sdp}", string.IsNullOrEmpty(request.Body) ? "(无 SDP)" : request.Body);

        // Stateless 模式下 INVITE 可能重传, 检查是否已存在同一 Call-ID 的会话
        var existingSession = _callManager.FindByCallerCallId(request.Header.CallId);
        if (existingSession != null)
        {
            _logger.LogDebug("INVITE 重传: CallId={CallId}, 会话已存在, 回复缓存的响应", request.Header.CallId);
            await SendResponse(request, SIPResponseStatusCodesEnum.Trying, "Trying", remoteEP);
            if (existingSession.ForwardedCallerOkResponse != null)
                await _sipTransport!.SendResponseAsync(existingSession.CallerRemoteEP, existingSession.ForwardedCallerOkResponse);
            return;
        }

        // 查找主叫是否已注册 (简单验证来源合法性)
        var callerReg = _registrationStore.GetRegistration(callerNumber);
        if (callerReg == null)
        {
            _logger.LogWarning("主叫分机 {Number} 未注册", callerNumber);
            await SendResponse(request, SIPResponseStatusCodesEnum.Forbidden, "Not registered", remoteEP);
            return;
        }

        // 查找被叫是否已注册
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
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "向被叫 {Number} 发送 INVITE 失败", calleeNumber);
            await SendResponse(request, SIPResponseStatusCodesEnum.ServiceUnavailable, "Destination unreachable", remoteEP);
            _callManager.RemoveSession(session);
        }
    }

    /// <summary>
    /// 创建 B2BUA 被叫侧 INVITE 请求
    /// </summary>
    private SIPRequest CreateB2BUAInvite(SIPRequest originalInvite, RegisteredExtension callee, SIPEndPoint targetEP)
    {
        var callerNumber = originalInvite.Header.From.FromURI.User;

        // 新的 Request-URI 指向被叫的 Contact
        var requestUri = callee.ContactURI.CopyOf();

        // 创建新的 INVITE
        var invite = SIPRequest.GetRequest(SIPMethodsEnum.INVITE, requestUri);

        // From: 用主叫号但新 tag
        var fromUri = new SIPURI(callerNumber, targetEP.Address.ToString(), null, SIPSchemesEnum.sip);
        invite.Header.From = new SIPFromHeader(null, fromUri, CallProperties.CreateNewCallId()[..8]);

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
                    }
                    _logger.LogInformation("转发 {Status} 给主叫: CallId={CallId}", response.Status, session.CallerCallId);
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

                    var busyResponse = SIPResponse.GetResponse(session.CallerInvite, response.Status, response.ReasonPhrase);
                    busyResponse.Header.To.ToTag = session.B2buaToTag;
                    AddAdvertisedContact(busyResponse, callerContactEP);
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

        // 向另一侧转发 BYE (仅当另一侧尚未挂断时)
        if (isFromCaller && !session.CalleeHungUp && session.CalleeInvite != null)
        {
            // 主叫挂断，向被叫发 BYE
            session.ByeTargetIsCallee = true;
            await SendByeToCallee(session);
            session.ByeSentAt = DateTime.UtcNow;
        }
        else if (!isFromCaller && !session.CallerHungUp && session.CallerInvite != null)
        {
            // 被叫挂断，向主叫发 BYE
            session.ByeTargetIsCallee = false;
            await SendByeToCaller(session);
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

    private async Task SendByeToCallee(CallSession session)
    {
        if (session.CalleeInvite == null) return;

        var calleeContactEP = GetContactEPForClient(session.CalleeRemoteEP);

        var byeRequest = SIPRequest.GetRequest(SIPMethodsEnum.BYE, session.CalleeInvite.URI.CopyOf());
        byeRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        byeRequest.Header.From = session.CalleeInvite.Header.From;
        var toUri = new SIPURI(session.CalleeNumber, calleeContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
        byeRequest.Header.To = new SIPToHeader(null, toUri, session.CalleeToTag);
        byeRequest.Header.CSeq = session.CalleeInvite.Header.CSeq + 1;
        byeRequest.Header.Vias.PushViaHeader(new SIPViaHeader(calleeContactEP, CallProperties.CreateNewCallId()[..16]));
        byeRequest.Header.MaxForwards = 70;
        var contactUri = new SIPURI(SIPSchemesEnum.sip, calleeContactEP);
        byeRequest.Header.Contact = [new SIPContactHeader(null, contactUri)];

        await _sipTransport!.SendRequestAsync(session.CalleeRemoteEP, byeRequest);
        _logger.LogInformation("BYE 已发送给被叫: {Callee}", session.CalleeNumber);
    }

    private async Task SendByeToCaller(CallSession session)
    {
        if (session.CallerInvite == null) return;

        var callerContactEP = GetContactEPForClient(session.CallerRemoteEP);

        var byeRequest = SIPRequest.GetRequest(SIPMethodsEnum.BYE, session.CallerInvite.URI.CopyOf());
        byeRequest.Header.CallId = session.CallerInvite.Header.CallId;
        var fromUri = new SIPURI(session.CalleeNumber, callerContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
        byeRequest.Header.From = new SIPFromHeader(null, fromUri, session.B2buaToTag);
        var toUri = new SIPURI(session.CallerNumber, callerContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
        byeRequest.Header.To = new SIPToHeader(null, toUri, session.CallerFromTag);
        byeRequest.Header.CSeq = session.CallerInvite.Header.CSeq + 1;
        byeRequest.Header.Vias.PushViaHeader(new SIPViaHeader(callerContactEP, CallProperties.CreateNewCallId()[..16]));
        byeRequest.Header.MaxForwards = 70;
        var contactUri = new SIPURI(SIPSchemesEnum.sip, callerContactEP);
        byeRequest.Header.Contact = [new SIPContactHeader(null, contactUri)];

        await _sipTransport!.SendRequestAsync(session.CallerRemoteEP, byeRequest);
        _logger.LogInformation("BYE 已发送给主叫: {Caller}", session.CallerNumber);
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

    // ===== 工具方法 =====

    private async Task SendResponse(SIPRequest request, SIPResponseStatusCodesEnum status, string reason, SIPEndPoint remoteEP)
    {
        var response = SIPResponse.GetResponse(request, status, reason);
        await _sipTransport!.SendResponseAsync(remoteEP, response);
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
