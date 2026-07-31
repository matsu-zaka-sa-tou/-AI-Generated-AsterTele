using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SIPSorcery.SIP;
using SIPSorcery.SIP.App;
using System.Net;
using System.Net.Sockets;

namespace AsterTele;

/// <summary>
/// INVITE 相关逻辑处理器
/// 从 SipSoftSwitch 中提取，处理所有 INVITE 相关的 SIP 信令
/// 包括: 入站路由、外呼构建、B2BUA INVITE/响应转发、ACK/CANCEL 处理、呼叫转移
/// </summary>
internal class InviteHandler
{
    private readonly SipTransportContext _ctx;
    private readonly ILogger<InviteHandler> _logger;
    private readonly SipOptions _options;
    private readonly RuntimeOptions _runtime;
    private readonly ICallManager _callManager;
    private readonly IRegistrationStore _registrationStore;
    private readonly ITrunkManager _trunkManager;
    private readonly IRtpBridge _rtpBridge;
    private readonly Func<CallSession, string?, Task> _sendByeToCallee;

    private SIPTransport Transport => _ctx.Transport ?? throw new InvalidOperationException("SIP 传输层未初始化");

    public InviteHandler(
        SipTransportContext ctx,
        ILogger<InviteHandler> logger,
        IOptions<SipOptions> options,
        ICallManager callManager,
        IRegistrationStore registrationStore,
        ITrunkManager trunkManager,
        IRtpBridge rtpBridge,
        Func<CallSession, string?, Task> sendByeToCallee)
    {
        _ctx = ctx;
        _logger = logger;
        _options = options.Value;
        _runtime = _options.Runtime;
        _callManager = callManager;
        _registrationStore = registrationStore;
        _trunkManager = trunkManager;
        _rtpBridge = rtpBridge;
        _sendByeToCallee = sendByeToCallee;
    }

    // ===== INVITE 处理 =====

    internal async Task HandleInvite(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
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
                        await Transport.SendResponseAsync(existingSession.CallerRemoteEP, existingSession.ForwardedCallerOkResponse);
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
            t.Enabled && NetworkUtility.IsFromTrunkNetwork(remoteEP, _options, _logger));

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
        var calleeTargetEP = NetworkUtility.GetContactEPForClient(new SIPEndPoint(SIPProtocolsEnum.udp,
            calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port), _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
        var calleeInvite = CreateB2BUAInvite(request, calleeReg, calleeTargetEP, session);

        // 发送 INVITE 给被叫
        try
        {
            _logger.LogInformation("向被叫 {Number} ({Contact}) 发送 INVITE", calleeNumber, calleeReg.ContactURI);
            var calleeEP = new SIPEndPoint(SIPProtocolsEnum.udp,
                calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port);
            await Transport.SendRequestAsync(calleeEP, calleeInvite);
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
        if (_ctx.Transport == null) return;

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
        var trunkEP = SipUriUtility.ResolveSipUriEndPoint(trunkRegistrarUri, _options.DnsServer, _logger);

        // 使用 Trunk 的 OutboundAddress 作为 Contact/SDP 地址 (运营商侧看到的公网 IP)
        // Via sent-by 使用内网 IP + trunk 传输层实际端口 (MicroSIP 抓包确认)
        var (trunkOutIp, _) = _trunkManager.GetOutboundAddress(trunk);
        var trunkTransportEP = _trunkManager.GetTrunkTransportEP();

        // Via sent-by: 使用本机内网 IP + trunk 传输层端口
        var localIP = NetworkUtility.GetLocalIPv4();
        var trunkViaEP = new SIPEndPoint(SIPProtocolsEnum.udp,
            System.Net.IPAddress.Parse(localIP), trunkTransportEP.Port);

        // === 中国电信 IMS 外呼 INVITE 格式要求 ===
        // Request-URI: 使用 tel: 格式 (如 tel:+8610000), 运营商 IMS 期望此格式
        // To: 使用 sip: 格式 (sip:10000@bac26.cq.ctcims.cn)
        // From: 使用 sip: 格式, user=主叫号码 (或 Trunk 号码)
        var trunkNumber = trunk.FromUser ?? trunk.Username.Split('@')[0];

        // Request-URI: tel:+86<号码> 格式 (中国电信 IMS 要求)
        // 如果号码不以 +86 开头且长度 >= 7 (固话/手机号), 自动添加 +86 前缀
        // 短号/服务号 (如 110, 10000, 10086) 长度 <= 6, 不加 +86
        var outboundNumber = actualNumber;
        if (!outboundNumber.StartsWith("+") && outboundNumber.Length >= 7)
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
        trunkInvite.Header.MaxForwards = _runtime.MaxForwards;

        // Contact: MicroSIP 抓包使用本地 IP + 端口 (192.168.40.140:54625;ob)
        var contactUri = new SIPURI(trunkNumber, $"{localIP}:{trunkTransportEP.Port}", null, SIPSchemesEnum.sip);
        contactUri.Parameters.Set("ob", null);
        trunkInvite.Header.Contact = [new SIPContactHeader(displayName, contactUri)];

        // Route: 强制下一跳为运营商 SIP 代理 (无 :5060 端口, 与 REGISTER 一致)
        var routeUri = SIPURI.ParseSIPURI($"sip:{trunkRegistrarUri.HostAddress}");
        trunkInvite.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

        // SDP: RTP 媒体锚定 — 如果 IRtpBridge 支持, 将 SDP 重写为 AsterTele 的地址/端口
        // 否则回退到纯透传模式 (仅替换 IP)
        if (!string.IsNullOrEmpty(request.Body))
        {
            var sdpBody = _rtpBridge.RewriteSdpToCallee(session, request.Body, trunkOutIp);
            if (sdpBody == null)
            {
                // NullRtpBridge: 纯透传, 仅替换 IP
                sdpBody = request.Body;
                if (!string.IsNullOrEmpty(trunkOutIp))
                    sdpBody = SdpUtility.ReplaceSdpIpAddress(sdpBody, trunkOutIp);
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
    internal async Task HandleOutboundInviteAuthChallenge(
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
        var localIP = NetworkUtility.GetLocalIPv4();
        var trunkViaEP = new SIPEndPoint(SIPProtocolsEnum.udp,
            System.Net.IPAddress.Parse(localIP), trunkTransportEP.Port);

        // 外呼号码加 +86 前缀 (与 HandleOutboundInvite 一致)
        // 短号/服务号 (如 110, 10000, 10086) 长度 <= 6, 不加 +86
        var outboundNumber = session.CalleeNumber;
        if (!outboundNumber.StartsWith("+") && outboundNumber.Length >= 7)
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
        reinvite.Header.MaxForwards = _runtime.MaxForwards;

        // Contact: 使用本地 IP + 端口 (与 REGISTER 一致)
        var reinviteContactUri = new SIPURI(trunkNumber, $"{localIP}:{trunkTransportEP.Port}", null, SIPSchemesEnum.sip);
        reinviteContactUri.Parameters.Set("ob", null);
        reinvite.Header.Contact = [new SIPContactHeader(displayName, reinviteContactUri)];

        // Route: 无 :5060 端口 (与 REGISTER 一致)
        var routeUri = SIPURI.ParseSIPURI($"sip:{trunkRegistrarUri.HostAddress}");
        reinvite.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

        // Authorization URI: 使用 IMS 域 (sip:cq.ctcims.cn)
        var authDigestUri = $"sip:{clientUriHost}";
        var authDigest = DigestUtility.BuildManualDigest(
            trunk.Username, trunk.Password,
            !string.IsNullOrEmpty(trunk.Realm) ? trunk.Realm : authDigestRaw.Realm ?? "",
            authDigestRaw.Nonce ?? "", authDigestRaw.Qop ?? "auth",
            authDigestRaw.URI ?? authDigestUri,
            SIPMethodsEnum.INVITE.ToString(),
            authDigestRaw.Opaque ?? "");

        var authHeader = new SIPAuthenticationHeader(authDigest);
        reinvite.Header.AuthenticationHeaders.Add(authHeader);

        // SDP: RTP 媒体锚定 (同外呼 INVITE, 重写为 AsterTele 地址/端口)
        if (session.CallerInvite != null && !string.IsNullOrEmpty(session.CallerInvite.Body))
        {
            var sdpBody = _rtpBridge.RewriteSdpToCallee(session, session.CallerInvite.Body, trunkOutIp);
            if (sdpBody == null)
            {
                sdpBody = session.CallerInvite.Body;
                if (!string.IsNullOrEmpty(trunkOutIp))
                    sdpBody = SdpUtility.ReplaceSdpIpAddress(sdpBody, trunkOutIp);
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
            var advEP = NetworkUtility.GetContactEPForClient(remoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
            var contactUri = new SIPURI(SIPSchemesEnum.sip, advEP);
            okResponse.Header.Contact = [new SIPContactHeader(null, contactUri)];
        }

        // Supported 头 (避免运营商发 PRACK 等我们不支持的功能)
        okResponse.Header.Supported = "replaces, outbound";

        // 更新运营商 Contact URI (re-INVITE 可能携带新的 Contact)
        var reInviteContact = reInvite.Header.Contact.FirstOrDefault();
        if (reInviteContact != null)
        {
            session.CallerContactURI = reInviteContact.ContactURI.CopyOf();
            _logger.LogInformation("re-INVITE 更新运营商 Contact: {URI}", session.CallerContactURI);
        }

        await Transport.SendResponseAsync(remoteEP, okResponse);
        _logger.LogInformation("re-INVITE 已回复 200 OK (保持原会话): CallId={CallId}", reInvite.Header.CallId);
    }

    /// <summary>
    /// 创建 B2BUA 被叫侧 INVITE 请求
    /// </summary>
    private SIPRequest CreateB2BUAInvite(SIPRequest originalInvite, RegisteredExtension callee, SIPEndPoint targetEP, CallSession session)
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
        invite.Header.MaxForwards = _runtime.MaxForwards;

        // User-Agent
        invite.Header.UserAgent = "AsterTele/1.0";

        // Allow
        invite.Header.Allow = "INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER";

        // SDP: 入站 INVITE 的 RTP 媒体锚定
        // 将运营商 SDP 重写为 AsterTele 的地址/端口, 让本地分机的 RTP 发到 AsterTele
        // 使用 Rtp.MediaAddress (192.168.40.102): 本地分机可直接路由到达
        // 对运营商侧用 OutboundAddress (172.48.242.167), 由路由器 DNAT 转发到本机
        if (!string.IsNullOrEmpty(originalInvite.Body))
        {
            var extensionSideIp = _options.Rtp.MediaAddress ?? NetworkUtility.GetLocalIPv4();

            var sdpBody = _rtpBridge.RewriteSdpToCallee(session, originalInvite.Body, extensionSideIp);
            if (sdpBody == null)
                sdpBody = originalInvite.Body; // 纯透传

            invite.Body = sdpBody;
            invite.Header.ContentType = originalInvite.Header.ContentType;
            invite.Header.ContentLength = sdpBody.Length;
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

    internal async Task ForwardCalleeResponse(SIPResponse response, SIPEndPoint localEP, SIPEndPoint remoteEP)
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
            var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);

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
                        // SDP: RTP 媒体锚定 — 重写被叫 SDP 为主叫侧 AsterTele 地址/端口
                        // 使用 Rtp.MediaAddress (192.168.40.102): 主叫可直接路由到达
                        // SIP Contact/Record-Route 仍用 AdvertisedAddress (路由器IP, 经端口转发)
                        var callerSideIp = _options.Rtp.MediaAddress ?? NetworkUtility.GetLocalIPv4();
                        var sdpBody = _rtpBridge.RewriteSdpToCaller(session, response.Body, callerSideIp);
                        if (sdpBody == null)
                            sdpBody = response.Body; // 纯透传

                        ringingResponse.Body = sdpBody;
                        ringingResponse.Header.ContentType = response.Header.ContentType;
                        ringingResponse.Header.ContentLength = sdpBody.Length;
                        // 183 Session Progress 带 SDP = 早期媒体 (early media)
                        // RTP 锚定后, 客户端收到 AsterTele 的地址, 忙音/提示音将正常转发
                        if (response.Status == SIPResponseStatusCodesEnum.SessionProgress)
                            _logger.LogInformation("183 Session Progress 携带 SDP (早期媒体), RTP 已锚定: CallId={CallId}", session.CallerCallId);
                    }
                    _logger.LogInformation("转发 {Status} 给主叫: CallId={CallId}, SDP={HasSdp}",
                        response.Status, session.CallerCallId, !string.IsNullOrEmpty(response.Body));
                    await Transport.SendResponseAsync(session.CallerRemoteEP, ringingResponse);
                    break;

                case SIPResponseStatusCodesEnum.Ok:
                    if (session.Callee200OkProcessed)
                    {
                        session.Callee200OkRetransmitCount++;
                        _logger.LogDebug("被叫 200 OK 重传 #{Count}", session.Callee200OkRetransmitCount);

                        // 重传 200 OK 给主叫
                        if (session.ForwardedCallerOkResponse != null)
                            await Transport.SendResponseAsync(session.CallerRemoteEP, session.ForwardedCallerOkResponse);

                        // 200 OK 重传到达说明主叫的 ACK 没到服务器
                        // Proxy ACK 已在首次 200 OK 时发送, 这里只是继续重传 200 OK 给主叫
                        // 兜底: 超过 11 次重传 (~32s) 且 ACK 也没成功, 主动发 BYE 结束
                        if (session.Callee200OkRetransmitCount > _runtime.OkRetransmitMaxCount && !session.ByeProcessed)
                        {
                            _logger.LogWarning("被叫 200 OK 重传超限, 主动向被叫 {Callee} 发送 BYE", session.CalleeNumber);
                            session.ByeProcessed = true;
                            await _sendByeToCallee(session, null);
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
                        // SDP: RTP 媒体锚定 — 重写被叫 SDP 为主叫侧 AsterTele 地址/端口
                        // 使用 Rtp.MediaAddress (192.168.40.102): 主叫可直接路由到达
                        var callerSideIp = _options.Rtp.MediaAddress ?? NetworkUtility.GetLocalIPv4();
                        var sdpBody = _rtpBridge.RewriteSdpToCaller(session, response.Body, callerSideIp);
                        if (sdpBody == null)
                            sdpBody = response.Body; // 纯透传

                        okResponse.Body = sdpBody;
                        okResponse.Header.ContentType = response.Header.ContentType;
                        okResponse.Header.ContentLength = sdpBody.Length;
                    }
                    session.ForwardedCallerOkResponse = okResponse;
                    _logger.LogInformation("转发 200 OK 给主叫: CallId={CallId}", session.CallerCallId);
                    _logger.LogDebug("200 OK 详情: Contact={Contact}, ViaTop={Via}",
                        okResponse.Header.Contact.FirstOrDefault()?.ContactURI,
                        okResponse.Header.Vias.Via.FirstOrDefault());
                    await Transport.SendResponseAsync(session.CallerRemoteEP, okResponse);
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
                    if (busyForwardRule != null && session.ForwardDepth < _runtime.MaxForwardDepth)
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
                    await Transport.SendResponseAsync(session.CallerRemoteEP, busyResponse);
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
                        await Transport.SendResponseAsync(session.CallerRemoteEP, errResponse);
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

        var calleeContactEP = NetworkUtility.GetContactEPForClient(session.CalleeRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);

        var ackRequest = SIPRequest.GetRequest(SIPMethodsEnum.ACK, session.CalleeInvite.URI.CopyOf());
        ackRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        ackRequest.Header.From = session.CalleeInvite.Header.From;
        ackRequest.Header.To = session.CalleeInvite.Header.To;
        if (session.CalleeToTag != null && string.IsNullOrEmpty(ackRequest.Header.To.ToTag))
            ackRequest.Header.To.ToTag = session.CalleeToTag;
        ackRequest.Header.CSeq = session.CalleeInvite.Header.CSeq;
        ackRequest.Header.Vias.PushViaHeader(new SIPViaHeader(calleeContactEP, CallProperties.CreateNewCallId()[..16]));
        ackRequest.Header.MaxForwards = _runtime.MaxForwards;

        await Transport.SendRequestAsync(session.CalleeRemoteEP, ackRequest);
        _logger.LogInformation("Proxy ACK 已发送给被叫: {Callee} (代替主叫)", session.CalleeNumber);
    }

    internal async Task HandleAck(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
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
        ackRequest.Header.Vias.PushViaHeader(new SIPViaHeader(NetworkUtility.GetContactEPForClient(session.CalleeRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger), CallProperties.CreateNewCallId()[..16]));
        ackRequest.Header.MaxForwards = _runtime.MaxForwards;

        // 透传 ACK 的 SDP (如果有的话，某些客户端在 ACK 中带 SDP)
        if (!string.IsNullOrEmpty(request.Body))
        {
            ackRequest.Body = request.Body;
            ackRequest.Header.ContentType = request.Header.ContentType;
            ackRequest.Header.ContentLength = request.Body.Length;
            _logger.LogDebug("ACK 带 SDP:\n{Sdp}", request.Body);
        }

        await Transport.SendRequestAsync(session.CalleeRemoteEP, ackRequest);
        _logger.LogInformation("ACK 已转发给被叫: {Callee} EP={EP}", session.CalleeNumber, session.CalleeRemoteEP);
    }

    // ===== CANCEL 处理 =====

    internal async Task HandleCancel(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
    {
        _logger.LogInformation("CANCEL: CallId={CallId}", request.Header.CallId);

        var session = _callManager.FindByCallerCallId(request.Header.CallId);
        if (session == null)
        {
            await SendResponse(request, SIPResponseStatusCodesEnum.CallLegTransactionDoesNotExist, "Call not found", remoteEP);
            return;
        }

        var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);

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

            await Transport.SendRequestAsync(session.CalleeRemoteEP, cancelRequest);

            // 向主叫发送 487 Request Terminated (带 B2BUA To tag + Contact)
            var terminatedResponse = SIPResponse.GetResponse(session.CallerInvite,
                SIPResponseStatusCodesEnum.RequestTerminated, "Request Terminated");
            terminatedResponse.Header.To.ToTag = session.B2buaToTag;
            AddAdvertisedContact(terminatedResponse, callerContactEP);
            await Transport.SendResponseAsync(session.CallerRemoteEP, terminatedResponse);
        }

        _callManager.RemoveSession(session);
        _logger.LogInformation("呼叫已取消: {Caller} -> {Callee}", session.CallerNumber, session.CalleeNumber);
    }

    // ===== ACK for non-2xx =====

    /// <summary>
    /// B2BUA 代替主叫向被叫发 ACK for non-2xx (停止被叫重传 486/487 等)
    /// 在 stateless 模式下, UAS 事务引擎不会自动发 ACK for non-2xx, 必须手动处理
    /// </summary>
    private async Task SendAckForNon2xxToCallee(CallSession session, SIPResponse calleeResponse)
    {
        if (session.CalleeInvite == null) return;

        var calleeContactEP = NetworkUtility.GetContactEPForClient(session.CalleeRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);

        var ackRequest = SIPRequest.GetRequest(SIPMethodsEnum.ACK, session.CalleeInvite.URI.CopyOf());
        ackRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        ackRequest.Header.From = session.CalleeInvite.Header.From;
        ackRequest.Header.To = session.CalleeInvite.Header.To;
        // 复制响应中的 To tag (被叫已添加了自己的 tag)
        if (!string.IsNullOrEmpty(calleeResponse.Header.To.ToTag))
            ackRequest.Header.To.ToTag = calleeResponse.Header.To.ToTag;
        ackRequest.Header.CSeq = session.CalleeInvite.Header.CSeq; // CSeq 号与 INVITE 相同, method=ACK
        ackRequest.Header.Vias.PushViaHeader(new SIPViaHeader(calleeContactEP, CallProperties.CreateNewCallId()[..16]));
        ackRequest.Header.MaxForwards = _runtime.MaxForwards;

        await Transport.SendRequestAsync(session.CalleeRemoteEP, ackRequest);
        _logger.LogInformation("ACK for non-2xx 已发送给被叫: {Callee} (status={Status})",
            session.CalleeNumber, calleeResponse.Status);
    }

    // ===== 呼叫转移 =====

    /// <summary>
    /// 处理语音信箱转移 (骨架)
    /// 当前阶段: 记录日志 + 向主叫返回 486 Busy (因无 RTP 音频能力)
    /// 后续: 应答呼叫 → 播放提示音 → 录音 → 保存留言
    /// </summary>
    private async Task HandleVoiceMailForward(CallSession session)
    {
#pragma warning disable CS0618 // VoiceMailSession 已标记 Obsolete，此使用点待后续迭代替换
        var vmSession = new VoiceMailSession
        {
            MailboxExtension = session.CalleeNumber,
            CallerNumber = session.CallerNumber,
            State = VoiceMailState.WaitingForAnswer
        };
#pragma warning restore CS0618

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
        var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
        AddAdvertisedContact(vmResp, callerContactEP);
        await Transport.SendResponseAsync(session.CallerRemoteEP, vmResp);

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
        if (_ctx.Transport == null) return;

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
        if (session.ForwardDepth > _runtime.MaxForwardDepth)
        {
            _logger.LogWarning("转移深度超限 ({Depth}), 停止转移", session.ForwardDepth);
            var loopResp = SIPResponse.GetResponse(session.CallerInvite,
                SIPResponseStatusCodesEnum.LoopDetected, "Forward loop detected");
            loopResp.Header.To.ToTag = session.B2buaToTag;
            var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
            AddAdvertisedContact(loopResp, callerContactEP);
            await Transport.SendResponseAsync(session.CallerRemoteEP, loopResp);
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
            var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
            AddAdvertisedContact(notFoundResp, callerContactEP);
            await Transport.SendResponseAsync(session.CallerRemoteEP, notFoundResp);
            _callManager.RemoveSession(session);
            return;
        }

        // 重新发送 180 Ringing 给主叫 (表示正在转接中)
        var ringingResp = SIPResponse.GetResponse(session.CallerInvite,
            SIPResponseStatusCodesEnum.Ringing, "Ringing");
        ringingResp.Header.To.ToTag = session.B2buaToTag;
        var callerCEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
        AddAdvertisedContact(ringingResp, callerCEP);
        AddRecordRoute(ringingResp, callerCEP);
        await Transport.SendResponseAsync(session.CallerRemoteEP, ringingResp);

        // 创建新的 B2BUA INVITE 给转移目标
        var calleeTargetEP = NetworkUtility.GetContactEPForClient(new SIPEndPoint(SIPProtocolsEnum.udp,
            calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port), _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
        var calleeInvite = CreateB2BUAInvite(session.CallerInvite, calleeReg, calleeTargetEP, session);
        session.CalleeNumber = calleeReg.Number;

        try
        {
            var calleeEP = new SIPEndPoint(SIPProtocolsEnum.udp,
                calleeReg.SourceEndPoint.Address, calleeReg.SourceEndPoint.Port);
            _logger.LogInformation("向转移目标 {Number} ({Contact}) 发送 INVITE", calleeReg.Number, calleeReg.ContactURI);
            await Transport.SendRequestAsync(calleeEP, calleeInvite);
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
            var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);
            AddAdvertisedContact(errResp, callerContactEP);
            await Transport.SendResponseAsync(session.CallerRemoteEP, errResp);
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
        if (_ctx.Transport == null || session.CalleeInvite == null) return;

        var cancelRequest = SIPRequest.GetRequest(SIPMethodsEnum.CANCEL, session.CalleeInvite.URI);
        cancelRequest.Header.CallId = session.CalleeCallId;
        cancelRequest.Header.From = session.CalleeInvite.Header.From;
        cancelRequest.Header.To = session.CalleeInvite.Header.To;
        cancelRequest.Header.CSeq = session.CalleeInvite.Header.CSeq;
        cancelRequest.Header.Vias = session.CalleeInvite.Header.Vias;
        cancelRequest.Header.MaxForwards = _runtime.MaxForwards;

        await Transport.SendRequestAsync(session.CalleeRemoteEP, cancelRequest);
        _logger.LogInformation("CANCEL 已发送给被叫: {Callee}", session.CalleeNumber);
    }

    // ===== 工具方法 =====

    private async Task SendResponse(SIPRequest request, SIPResponseStatusCodesEnum status, string reason, SIPEndPoint remoteEP)
    {
        var response = SIPResponse.GetResponse(request, status, reason);
        await Transport.SendResponseAsync(remoteEP, response);
    }
}
