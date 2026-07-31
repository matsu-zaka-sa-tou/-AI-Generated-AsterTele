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

        // To: 直接复制 INVITE 的 To URI (保证与 dialog 一致), 加上 200 OK 中获得的 To tag
        var toUri = session.CalleeInvite.Header.To.ToURI.CopyOf();
        byeRequest.Header.To = new SIPToHeader(null, toUri, session.CalleeToTag);
        byeRequest.Header.CSeq = session.CalleeInvite.Header.CSeq + 1;
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

        // Route: 如果 INVITE 有 Record-Route, BYE 也需要 Route 头 (按 RFC 3261 顺序)
        // UAS (被叫侧) 的 Route set = Record-Route 的反转
        // PushRoute 是前插 (Insert(0)), 所以按原始顺序 push 即可得到反转结果
        var calleeRecordRoutes = session.CalleeInvite.Header.RecordRoutes;
        if (calleeRecordRoutes != null && calleeRecordRoutes.Length > 0)
        {
            for (int i = 0; i < calleeRecordRoutes.Length; i++)
            {
                byeRequest.Header.Routes.PushRoute(calleeRecordRoutes.GetAt(i));
            }
        }

        await Transport.SendRequestAsync(session.CalleeRemoteEP, byeRequest);
        _logger.LogInformation("BYE 已发送给被叫: {Callee} EP={EP}", session.CalleeNumber, session.CalleeRemoteEP);
    }

    // ===== 发送 BYE 给主叫 =====

    private async Task SendByeToCaller(CallSession session, string? reason = null)
    {
        if (session.CallerInvite == null) return;

        var callerContactEP = NetworkUtility.GetContactEPForClient(session.CallerRemoteEP, _ctx.LocalEP, _ctx.AdvertisedEP, _logger);

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

        // Route: 如果运营商 INVITE 有 Record-Route, BYE 也需要 Route 头
        // UAS (我们收了运营商的 INVITE) 的 Route set = Record-Route 的反转
        // PushRoute 是前插 (Insert(0)), 所以按原始顺序 push 即可得到反转结果
        var callerRecordRoutes = session.CallerInvite.Header.RecordRoutes;
        if (callerRecordRoutes != null && callerRecordRoutes.Length > 0)
        {
            for (int i = 0; i < callerRecordRoutes.Length; i++)
            {
                byeRequest.Header.Routes.PushRoute(callerRecordRoutes.GetAt(i));
            }
        }

        await Transport.SendRequestAsync(session.CallerRemoteEP, byeRequest);
        _logger.LogInformation("BYE 已发送给主叫: {Caller} EP={EP}", session.CallerNumber, session.CallerRemoteEP);
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
