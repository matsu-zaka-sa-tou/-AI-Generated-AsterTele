using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// SIP 传输上下文
/// 封装 SIPTransport 及其关联的端点信息, 供各 Handler 共享
/// </summary>
internal sealed class SipTransportContext
{
    public SIPTransport? Transport { get; set; }
    public SIPEndPoint AdvertisedEP { get; set; } = SIPEndPoint.Empty;
    public SIPEndPoint LocalEP { get; set; } = SIPEndPoint.Empty;
}

/// <summary>
/// BYE 处理器
/// 从 SipSoftSwitch 提取的 BYE 相关逻辑
/// 处理 BYE 请求接收、转发、200 OK 确认、超时重传和会话清理
/// </summary>
internal class ByeHandler
{
    private readonly SipTransportContext _ctx;
    private readonly ILogger<ByeHandler> _logger;
    private readonly SipOptions _options;
    private readonly RuntimeOptions _runtime;
    private readonly ICallManager _callManager;
    private readonly ITrunkManager _trunkManager;
    private readonly IRtpBridge _rtpBridge;

    private SIPTransport Transport => _ctx.Transport
        ?? throw new InvalidOperationException("SIP 传输层未初始化");

    public ByeHandler(
        SipTransportContext ctx,
        ILogger<ByeHandler> logger,
        IOptions<SipOptions> options,
        ICallManager callManager,
        ITrunkManager trunkManager,
        IRtpBridge rtpBridge)
    {
        _ctx = ctx;
        _logger = logger;
        _options = options.Value;
        _runtime = _options.Runtime;
        _callManager = callManager;
        _trunkManager = trunkManager;
        _rtpBridge = rtpBridge;
    }

    // ===== BYE 200 OK 响应处理 =====

    internal Task HandleBye200Ok(SIPResponse response)
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
            _rtpBridge.OnSessionTerminated(session).ConfigureAwait(false).GetAwaiter();
            _callManager.RemoveSession(session);
        }

        return Task.CompletedTask;
    }

    // ===== BYE 请求处理 + 转发 =====

    internal async Task HandleBye(SIPRequest request, SIPEndPoint localEP, SIPEndPoint remoteEP)
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
            _rtpBridge.OnSessionTerminated(session).ConfigureAwait(false).GetAwaiter();
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

    // ===== 发送 BYE 给被叫 =====

    internal async Task SendByeToCallee(CallSession session, string? reason = null)
    {
        if (session.CalleeInvite == null) return;

        // 确定被叫侧 Contact EP (用于 Via/Contact 头)
        var calleeContactEP = NetworkUtility.GetContactEPForClient(session.CalleeRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);

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
            // 本地被叫: 使用 INVITE 的 Request-URI (即注册时的 Contact URI)
            // 不使用 200 OK Contact: NAT 后设备 200 OK Contact 可能是内网地址不可达
            // INVITE 的 Request-URI 是注册时的 Contact (经 SNAT 后可达), 旧版代码确认此行为正确
            byeRequestUri = session.CalleeInvite.URI.CopyOf();
            _logger.LogDebug("BYE Request-URI 使用 INVITE Request-URI: {URI}", byeRequestUri);
        }

        var byeRequest = SIPRequest.GetRequest(SIPMethodsEnum.BYE, byeRequestUri);
        byeRequest.Header.CallId = session.CalleeInvite.Header.CallId;
        byeRequest.Header.From = session.CalleeInvite.Header.From;

        // To: 直接复制 INVITE 的 To URI (保证与 dialog 一致), 加上 200 OK 中获得的 To tag
        var toUri = session.CalleeInvite.Header.To.ToURI.CopyOf();
        byeRequest.Header.To = new SIPToHeader(null, toUri, session.CalleeToTag);
        byeRequest.Header.CSeq = session.CalleeInviteCSeq + 1;
        byeRequest.Header.Vias.PushViaHeader(new SIPViaHeader(calleeContactEP, CallProperties.CreateNewCallId()[..16]));
        byeRequest.Header.MaxForwards = _runtime.MaxForwards;
        var contactUri = new SIPURI(SIPSchemesEnum.sip, calleeContactEP);
        byeRequest.Header.Contact = [new SIPContactHeader(null, contactUri)];

        // Reason 头: 透传原始 BYE 的 Reason (RFC 3326)
        // 让对端知道挂断原因 (如 User Busy, Normal Clearing 等)
        if (!string.IsNullOrEmpty(reason))
        {
            byeRequest.Header.Reason = reason;
            _logger.LogInformation("BYE 携带 Reason 头: {Reason}", reason);
        }

        // Route: 仅外呼 Trunk 通话才添加 Route 头 (运营商 SBC 需要路由)
        // 本地通话 (内机打内机) 不添加 Route:
        //   - AsterTele 是被叫侧 dialog 的 UAC, 按 RFC 3261 §12.1.2 路由集来自 200 OK 的 Record-Route
        //   - 本地设备 200 OK 通常不含 Record-Route, 所以路由集应为空
        //   - 如果把 INVITE 的 Record-Route (指向 AsterTele 自身) 拷贝进 Route,
        //     会导致 BYE 被路由回 AsterTele 自身而非送达被叫设备
        //   - 旧版代码不在本地通话 BYE 中添加 Route, 确认此行为正确
        if (session.IsOutboundTrunk)
        {
            var calleeRecordRoutes = session.CalleeInvite.Header.RecordRoutes;
            if (calleeRecordRoutes != null && calleeRecordRoutes.Length > 0)
            {
                for (int i = 0; i < calleeRecordRoutes.Length; i++)
                {
                    byeRequest.Header.Routes.PushRoute(calleeRecordRoutes.GetAt(i));
                }
                _logger.LogDebug("外呼Trunk BYE 添加 Route 头 (共 {Count} 条)", calleeRecordRoutes.Length);
            }
        }
        else
        {
            _logger.LogDebug("本地通话 BYE 不添加 Route 头");
        }

        await Transport.SendRequestAsync(session.CalleeRemoteEP, byeRequest);
        _logger.LogInformation("BYE → 被叫 {Callee} EP={EP} | RURI={RURI} | CSeq={CSeq} | CallId={CallId}",
            session.CalleeNumber, session.CalleeRemoteEP, byeRequestUri, byeRequest.Header.CSeq, byeRequest.Header.CallId);
    }

    // ===== 发送 BYE 给主叫 =====

    private async Task SendByeToCaller(CallSession session, string? reason = null)
    {
        if (session.CallerInvite == null) return;

        var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);

        // 确定 BYE Request-URI (三路分支: 入站Trunk / 内机打内机 / 外呼Trunk)
        SIPURI byeRequestUri;
        if (session.IsInboundTrunk)
        {
            // 入站Trunk方向: 主叫侧是运营商
            // BYE Request-URI 使用运营商 INVITE 的 Contact (已缓存在 session.CallerContactURI)
            if (session.CallerContactURI != null)
            {
                byeRequestUri = session.CallerContactURI.CopyOf();
                _logger.LogInformation("入站Trunk BYE Request-URI 使用运营商 Contact: {URI}", byeRequestUri);
            }
            else
            {
                // fallback: 用运营商的源 IP
                byeRequestUri = new SIPURI(session.CallerNumber,
                    session.CallerRemoteEP.Address.ToString(), null, SIPSchemesEnum.sip);
                _logger.LogWarning("无运营商 Contact, BYE Request-URI 使用源地址: {URI}", byeRequestUri);
            }
        }
        else if (session.IsOutboundTrunk)
        {
            // 外呼Trunk方向: 主叫侧是本地分机
            // BYE Request-URI 应使用分机的 Contact URI (而非 INVITE 的 Request-URI, 那是被叫号码)
            if (session.CallerContactURI != null)
            {
                byeRequestUri = session.CallerContactURI.CopyOf();
                _logger.LogInformation("外呼Trunk BYE Request-URI 使用本地分机 Contact: {URI}", byeRequestUri);
            }
            else
            {
                // fallback: 构造分机 Contact URI
                byeRequestUri = new SIPURI(session.CallerNumber,
                    session.CallerRemoteEP.Address.ToString(), null, SIPSchemesEnum.sip);
                _logger.LogWarning("无主叫 Contact URI, BYE Request-URI 使用构造地址: {URI}", byeRequestUri);
            }
        }
        else
        {
            // 内机打内机: 主叫侧是本地分机
            // BYE Request-URI 使用主叫分机的 Contact URI
            if (session.CallerContactURI != null)
            {
                byeRequestUri = session.CallerContactURI.CopyOf();
                _logger.LogInformation("内机打内机 BYE Request-URI 使用主叫 Contact: {URI}", byeRequestUri);
            }
            else
            {
                byeRequestUri = new SIPURI(session.CallerNumber,
                    session.CallerRemoteEP.Address.ToString(), null, SIPSchemesEnum.sip);
                _logger.LogWarning("无主叫 Contact, BYE Request-URI 使用源地址: {URI}", byeRequestUri);
            }
        }

        var byeRequest = SIPRequest.GetRequest(SIPMethodsEnum.BYE, byeRequestUri);
        byeRequest.Header.CallId = session.CallerInvite.Header.CallId;

        // 设置 From/To (三路分支)
        if (session.IsInboundTrunk)
        {
            // 入站Trunk: 我们是被叫侧, BYE 从我们发给运营商
            // From: 我们的身份 (To of original INVITE + our tag)
            // To: 运营商的身份 (From of original INVITE + their tag)
            byeRequest.Header.From = new SIPFromHeader(null,
                session.CallerInvite.Header.To.ToURI.CopyOf(), session.B2buaToTag);
            byeRequest.Header.To = new SIPToHeader(null,
                session.CallerInvite.Header.From.FromURI.CopyOf(), session.CallerFromTag);
        }
        else
        {
            // 外呼Trunk / 内机打内机: 主叫侧是本地分机
            // From: 被叫号码 (我们发给主叫时, From 是我们作为被叫侧的身份)
            // To: 主叫号码 (原始主叫, 带上他们的 From tag)
            var fromUri = new SIPURI(session.CalleeNumber, callerContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
            byeRequest.Header.From = new SIPFromHeader(null, fromUri, session.B2buaToTag);
            var toUri = new SIPURI(session.CallerNumber, callerContactEP.Address.ToString(), null, SIPSchemesEnum.sip);
            byeRequest.Header.To = new SIPToHeader(null, toUri, session.CallerFromTag);
        }

        // CSeq: 使用 CallerInviteCSeq (包含 re-INVITE 后的最新值) + 1
        // 注意: 不能直接用 session.CallerInvite.Header.CSeq, 因为 re-INVITE 只更新 CallerInviteCSeq
        // 如果通话中发生了 re-INVITE (CSeq 递增), 用原始 INVITE 的 CSeq 会导致 BYE CSeq 过时
        byeRequest.Header.CSeq = session.CallerInviteCSeq + 1;
        _logger.LogDebug("BYE CSeq={CSeq} (基于 CallerInviteCSeq={Base}, 含 re-INVITE 更新)",
            byeRequest.Header.CSeq, session.CallerInviteCSeq);

        byeRequest.Header.Vias.PushViaHeader(new SIPViaHeader(callerContactEP, CallProperties.CreateNewCallId()[..16]));
        byeRequest.Header.MaxForwards = _runtime.MaxForwards;
        var contactUri = new SIPURI(SIPSchemesEnum.sip, callerContactEP);
        byeRequest.Header.Contact = [new SIPContactHeader(null, contactUri)];

        // Reason 头: 透传原始 BYE 的 Reason (RFC 3326)
        // 让对端知道挂断原因 (如 User Busy, Normal Clearing 等)
        if (!string.IsNullOrEmpty(reason))
        {
            byeRequest.Header.Reason = reason;
            _logger.LogInformation("BYE 携带 Reason 头: {Reason}", reason);
        }

        // Route: 仅入站 Trunk 通话才添加 Route 头 (运营商 SBC 需要路由)
        // 本地通话 (内机打内机) / 外呼 Trunk 的主叫侧不添加 Route:
        //   - 入站 Trunk: 运营商 INVITE 的 Record-Route 指向运营商 SBC, BYE 需要路由回去
        //   - 本地/外呼: 主叫侧的 INVITE Record-Route 指向 AsterTele 自身,
        //     添加到 Route 会导致 BYE 路由回 AsterTele 而非送达主叫设备
        if (session.IsInboundTrunk)
        {
            var callerRecordRoutes = session.CallerInvite.Header.RecordRoutes;
            if (callerRecordRoutes != null && callerRecordRoutes.Length > 0)
            {
                for (int i = 0; i < callerRecordRoutes.Length; i++)
                {
                    byeRequest.Header.Routes.PushRoute(callerRecordRoutes.GetAt(i));
                }
                _logger.LogDebug("入站Trunk BYE 添加 Route 头 (共 {Count} 条)", callerRecordRoutes.Length);
            }
        }
        else
        {
            _logger.LogDebug("本地/外呼通话 BYE 不添加 Route 头");
        }

        // 详细 BYE 转发日志 (便于排查 From/To/CSeq/Request-URI 等问题)
        _logger.LogInformation("BYE → 主叫 {Caller} EP={EP} | RURI={RURI} | From={From} | To={To} | CSeq={CSeq} | CallId={CallId}",
            session.CallerNumber, session.CallerRemoteEP,
            byeRequestUri, byeRequest.Header.From, byeRequest.Header.To,
            byeRequest.Header.CSeq, byeRequest.Header.CallId);

        await Transport.SendRequestAsync(session.CallerRemoteEP, byeRequest);
    }

    // ===== 会话清理 =====

    /// <summary>
    /// 清理卡住的幽灵会话 + BYE 超时重传和强制清理
    /// - Initiating/Ringing 超 90 秒: 清理
    /// - Connected 超 2 小时: 清理
    /// - Disconnecting: BYE 重传 (5s 间隔, 最多 3 次), 超 20 秒强制清理
    /// - 双方都已挂断: 立即清理
    /// </summary>
    internal void CleanupStaleSessions()
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
                _rtpBridge.OnSessionTerminated(session).ConfigureAwait(false).GetAwaiter();
                _callManager.RemoveSession(session);
                continue;
            }

            // Disconnecting 状态: BYE 超时重传和强制清理
            if (session.State == CallState.Disconnecting && session.ByeSentAt.HasValue && !session.Bye200OkReceived)
            {
                var byeAge = now - session.ByeSentAt.Value;

                // BYE 重传: 每 5 秒重传一次, 最多 3 次
                if (byeAge > TimeSpan.FromSeconds(_runtime.ByeRetransmitIntervalSeconds * (session.ByeRetransmitCount + 1)) &&
                    session.ByeRetransmitCount < _runtime.ByeMaxRetransmitCount)
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
                if (byeAge > TimeSpan.FromSeconds(_runtime.ByeForcedCleanupSeconds))
                {
                    _logger.LogWarning("BYE 超时 20 秒未确认, 强制清理会话: {Session}", session);
                    _rtpBridge.OnSessionTerminated(session).ConfigureAwait(false).GetAwaiter();
                    _callManager.RemoveSession(session);
                }

                continue;
            }

            if ((session.State != CallState.Connected && age > TimeSpan.FromSeconds(_runtime.StaleSessionTimeoutSeconds)) ||
                (session.State == CallState.Connected && age > TimeSpan.FromHours(_runtime.MaxCallDurationHours)))
            {
                _logger.LogWarning("清理幽灵会话: {Session}, 存活={Age}", session, age);
                _rtpBridge.OnSessionTerminated(session).ConfigureAwait(false).GetAwaiter();
                _callManager.RemoveSession(session);
            }
        }
    }

    // ===== 辅助方法 =====

    private async Task SendResponse(SIPRequest request, SIPResponseStatusCodesEnum status, string reason, SIPEndPoint remoteEP)
    {
        var response = SIPResponse.GetResponse(request, status, reason);
        await Transport.SendResponseAsync(remoteEP, response);
    }
}
