using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// 活跃呼叫的 B2BUA 会话
/// 一路通话包含两条 SIP 对话腿 (Leg A = 主叫, Leg B = 被叫)
/// </summary>
public class CallSession
{
    /// <summary>会话 ID (唯一)</summary>
    public string SessionId { get; } = Guid.NewGuid().ToString("N")[..8];

    /// <summary>主叫分机号</summary>
    public string CallerNumber { get; set; } = string.Empty;

    /// <summary>被叫分机号</summary>
    public string CalleeNumber { get; set; } = string.Empty;

    /// <summary>主叫侧 SIP 请求 (原始 INVITE)</summary>
    public SIPRequest CallerInvite { get; set; } = null!;

    /// <summary>主叫侧远端地址</summary>
    public SIPEndPoint CallerRemoteEP { get; set; } = SIPEndPoint.Empty;

    /// <summary>被叫侧 SIP 请求 (服务端发出的 INVITE)</summary>
    public SIPRequest? CalleeInvite { get; set; }

    /// <summary>被叫侧远端地址</summary>
    public SIPEndPoint CalleeRemoteEP { get; set; } = SIPEndPoint.Empty;

    /// <summary>被叫侧 To tag (200 OK 中获得)</summary>
    public string? CalleeToTag { get; set; }

    /// <summary>是否已处理过被叫侧 200 OK (防止重传重复处理)</summary>
    public bool Callee200OkProcessed { get; set; }

    /// <summary>已转发给主叫的 200 OK 响应 (重传时直接复用)</summary>
    public SIPResponse? ForwardedCallerOkResponse { get; set; }

    /// <summary>ACK 是否已转发给被叫 (防止重复转发)</summary>
    public bool AckForwarded { get; set; }

    /// <summary>Proxy ACK 中 SDP 是否已透传 (防止重复设置 Body)</summary>
    public bool AckSdpForwarded { get; set; }

    /// <summary>B2BUA 为主叫侧 dialog 生成的 To tag (必须由服务端生成)</summary>
    public string B2buaToTag { get; } = Guid.NewGuid().ToString("N")[..8];

    /// <summary>BYE 是否已处理 (防止重传重复挂断)</summary>
    public bool ByeProcessed { get; set; }

    /// <summary>主叫侧是否已挂断 (收到主叫 BYE 或向主叫发了 BYE)</summary>
    public bool CallerHungUp { get; set; }

    /// <summary>被叫侧是否已挂断 (收到被叫 BYE 或向被叫发了 BYE)</summary>
    public bool CalleeHungUp { get; set; }

    /// <summary>BYE 的 200 OK 是否已收到 (停止重传)</summary>
    public bool Bye200OkReceived { get; set; }

    /// <summary>BYE 发送时间 (用于超时重传和清理)</summary>
    public DateTime? ByeSentAt { get; set; }

    /// <summary>BYE 重传次数</summary>
    public int ByeRetransmitCount { get; set; }

    /// <summary>BYE 目标: true=被叫, false=主叫</summary>
    public bool ByeTargetIsCallee { get; set; }

    /// <summary>是否为外呼 Trunk 会话</summary>
    public bool IsOutboundTrunk { get; set; }

    /// <summary>外呼 Trunk 名称</summary>
    public string? TrunkName { get; set; }

    /// <summary>主叫侧 From tag (从 INVITE 中提取)</summary>
    public string? CallerFromTag { get; set; }

    /// <summary>被叫 200 OK 重传计数</summary>
    public int Callee200OkRetransmitCount { get; set; }

    /// <summary>无应答超时取消令牌源</summary>
    public CancellationTokenSource? NoAnswerCts { get; set; }

    /// <summary>呼叫转移深度 (防止无限循环)</summary>
    public int ForwardDepth { get; set; }

    /// <summary>呼叫状态</summary>
    public CallState State { get; set; } = CallState.Initiating;

    /// <summary>创建时间</summary>
    public DateTime CreatedAt { get; } = DateTime.UtcNow;

    /// <summary>主叫侧 Call-ID</summary>
    public string CallerCallId => CallerInvite.Header.CallId;

    /// <summary>被叫侧 Call-ID</summary>
    public string? CalleeCallId => CalleeInvite?.Header.CallId;

    /// <summary>主叫侧 Contact URI (从运营商 INVITE 的 Contact 中提取, 用于发 BYE)</summary>
    public SIPURI? CallerContactURI { get; set; }

    /// <summary>主叫侧原始 INVITE 的 CSeq 序号 (用于区分重传 vs re-INVITE)</summary>
    public int CallerInviteCSeq { get; set; }

    /// <summary>被叫侧 Contact URI (从被叫 200 OK 的 Contact 中提取, 用于发 BYE)</summary>
    public SIPURI? CalleeContactURI { get; set; }

    /// <summary>通话接通时间 (200 OK 首次处理时记录, 用于计算通话时长)</summary>
    public DateTime? ConnectedAt { get; set; }

    /// <summary>被叫侧原始 INVITE 的 CSeq 序号 (用于区分重传 vs re-INVITE)</summary>
    public int CalleeInviteCSeq { get; set; }

    // ===== 状态机方法 (封装状态转换, 提供日志和校验) =====

    /// <summary>
    /// 安全状态转换: 校验合法转移并记录日志
    /// 不合法的转换会被拒绝并返回 false
    /// </summary>
    public bool TryTransitionTo(CallState newState, ILogger? logger = null)
    {
        var oldState = State;
        if (!IsValidTransition(oldState, newState))
        {
            logger?.LogWarning("非法状态转换: {Old} → {New} (SessionId={SessionId})", oldState, newState, SessionId);
            return false;
        }
        State = newState;
        logger?.LogDebug("会话状态转换: {Old} → {New} (SessionId={SessionId})", oldState, newState, SessionId);
        return true;
    }

    /// <summary>
    /// 标记主叫侧已挂断 (收到 BYE 或主动发 BYE)
    /// </summary>
    public void MarkCallerHungUp()
    {
        if (!CallerHungUp)
        {
            CallerHungUp = true;
            if (State == CallState.Connected || State == CallState.Disconnecting)
                State = CallState.Disconnecting;
        }
    }

    /// <summary>
    /// 标记被叫侧已挂断 (收到 BYE 或主动发 BYE)
    /// </summary>
    public void MarkCalleeHungUp()
    {
        if (!CalleeHungUp)
        {
            CalleeHungUp = true;
            if (State == CallState.Connected || State == CallState.Disconnecting)
                State = CallState.Disconnecting;
        }
    }

    /// <summary>
    /// 标记被叫侧 200 OK 已处理 (防止重传重复处理)
    /// </summary>
    public void MarkCallee200OkProcessed(string toTag, SIPEndPoint remoteEP)
    {
        if (Callee200OkProcessed) return;
        Callee200OkProcessed = true;
        CalleeToTag = toTag;
        CalleeRemoteEP = remoteEP.CopyOf();
        ConnectedAt = DateTime.UtcNow;
        State = CallState.Connected;
        NoAnswerCts?.Cancel();
    }

    /// <summary>
    /// 重置被叫腿状态 (用于呼叫转移时替换被叫)
    /// </summary>
    public void ResetCalleeLeg()
    {
        Callee200OkProcessed = false;
        Callee200OkRetransmitCount = 0;
        AckForwarded = false;
        AckSdpForwarded = false;
        ForwardedCallerOkResponse = null;
    }

    private static bool IsValidTransition(CallState from, CallState to)
    {
        return (from, to) switch
        {
            (CallState.Initiating, CallState.Ringing) => true,
            (CallState.Initiating, CallState.Connected) => true,
            (CallState.Initiating, CallState.Disconnected) => true,
            (CallState.Ringing, CallState.Connected) => true,
            (CallState.Ringing, CallState.Disconnecting) => true,
            (CallState.Ringing, CallState.Disconnected) => true,
            (CallState.Connected, CallState.Disconnecting) => true,
            (CallState.Connected, CallState.Disconnected) => true,
            (CallState.Disconnecting, CallState.Disconnected) => true,
            _ => false
        };
    }

    public override string ToString() => $"[{SessionId}] {CallerNumber} -> {CalleeNumber} ({State})";
}

public enum CallState
{
    Initiating,     // 正在发 INVITE
    Ringing,        // 被叫振铃
    Connected,      // 通话中
    Disconnecting,  // BYE 已处理, 等待对端确认
    Disconnected    // 已挂断
}

/// <summary>
/// 呼叫管理器
/// 管理所有活跃的 B2BUA 呼叫会话
/// </summary>
public class CallManager : ICallManager
{
    private readonly ConcurrentDictionary<string, CallSession> _sessionsByCallerCallId = new();
    private readonly ConcurrentDictionary<string, CallSession> _sessionsByCalleeCallId = new();
    private readonly ILogger<CallManager> _logger;

    public CallManager(ILogger<CallManager> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// 创建新呼叫会话
    /// </summary>
    public CallSession CreateSession(string callerNumber, string calleeNumber,
        SIPRequest callerInvite, SIPEndPoint callerRemoteEP)
    {
        var session = new CallSession
        {
            CallerNumber = callerNumber,
            CalleeNumber = calleeNumber,
            CallerInvite = callerInvite,
            CallerRemoteEP = callerRemoteEP,
            State = CallState.Initiating
        };

        _sessionsByCallerCallId[session.CallerCallId] = session;

        _logger.LogInformation("创建呼叫会话: {Session}", session);
        return session;
    }

    /// <summary>
    /// 通过主叫 Call-ID 查找会话
    /// </summary>
    public CallSession? FindByCallerCallId(string callId)
    {
        return _sessionsByCallerCallId.TryGetValue(callId, out var s) ? s : null;
    }

    /// <summary>
    /// 通过被叫 Call-ID 查找会话
    /// </summary>
    public CallSession? FindByCalleeCallId(string callId)
    {
        return _sessionsByCalleeCallId.TryGetValue(callId, out var s) ? s : null;
    }

    /// <summary>
    /// 通过分机号查找活跃会话 (无论该分机是主叫还是被叫)
    /// </summary>
    public CallSession? FindByExtension(string number)
    {
        var session = _sessionsByCallerCallId.Values
            .FirstOrDefault(s => s.CallerNumber == number || s.CalleeNumber == number);
        return session;
    }

    /// <summary>
    /// 注册被叫侧 Call-ID 关联
    /// </summary>
    public void RegisterCalleeLeg(CallSession session, SIPRequest calleeInvite, SIPEndPoint calleeRemoteEP)
    {
        session.CalleeInvite = calleeInvite;
        session.CalleeInviteCSeq = calleeInvite.Header.CSeq;
        session.CalleeRemoteEP = calleeRemoteEP;
        _sessionsByCalleeCallId[session.CalleeCallId!] = session;
        _logger.LogDebug("注册被叫腿: Session={SessionId}, CalleeCallId={CallId}", session.SessionId, session.CalleeCallId);
    }

    /// <summary>
    /// 标记会话为已连接
    /// </summary>
    public void MarkConnected(CallSession session)
    {
        session.State = CallState.Connected;
        session.ConnectedAt = DateTime.UtcNow;
        _logger.LogInformation("会话已连接: {Session}", session);
    }

    /// <summary>移除会话</summary>
    public void RemoveSession(CallSession session)
    {
        // 取消无应答定时器
        session.NoAnswerCts?.Cancel();
        session.NoAnswerCts?.Dispose();
        session.NoAnswerCts = null;

        _sessionsByCallerCallId.TryRemove(session.CallerCallId, out _);
        if (session.CalleeCallId != null)
            _sessionsByCalleeCallId.TryRemove(session.CalleeCallId, out _);
        session.State = CallState.Disconnected;
        _logger.LogInformation("会话已移除: {Session}", session);
    }

    /// <summary>
    /// 注销被叫侧 Call-ID 关联 (用于呼叫转移时替换被叫腿)
    /// </summary>
    public void UnregisterCalleeLeg(string calleeCallId)
    {
        _sessionsByCalleeCallId.TryRemove(calleeCallId, out _);
        _logger.LogDebug("注销被叫腿: CalleeCallId={CallId}", calleeCallId);
    }

    /// <summary>
    /// 移除指定分机号关联的所有会话 (防止幽灵会话)
    /// </summary>
    public void RemoveSessionByExtension(string number)
    {
        var toRemove = _sessionsByCallerCallId.Values
            .Where(s => s.CallerNumber == number || s.CalleeNumber == number)
            .ToList();

        foreach (var session in toRemove)
        {
            _logger.LogInformation("清理分机 {Number} 的旧会话: {Session}", number, session);
            RemoveSession(session);
        }
    }

    /// <summary>
    /// 获取所有活跃会话
    /// </summary>
    public IEnumerable<CallSession> GetActiveSessions()
    {
        return _sessionsByCallerCallId.Values.ToList();
    }
}
