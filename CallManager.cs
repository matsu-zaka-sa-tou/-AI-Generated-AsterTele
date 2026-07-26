using System.Collections.Concurrent;
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

    /// <summary>主叫侧 From tag (从 INVITE 中提取)</summary>
    public string? CallerFromTag { get; set; }

    /// <summary>被叫 200 OK 重传计数</summary>
    public int Callee200OkRetransmitCount { get; set; }

    /// <summary>呼叫状态</summary>
    public CallState State { get; set; } = CallState.Initiating;

    /// <summary>创建时间</summary>
    public DateTime CreatedAt { get; } = DateTime.UtcNow;

    /// <summary>主叫侧 Call-ID</summary>
    public string CallerCallId => CallerInvite.Header.CallId;

    /// <summary>被叫侧 Call-ID</summary>
    public string? CalleeCallId => CalleeInvite?.Header.CallId;

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
public class CallManager
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
        // 先查主叫
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
        _logger.LogInformation("会话已连接: {Session}", session);
    }

    /// <summary>
    /// 移除会话
    /// </summary>
    public void RemoveSession(CallSession session)
    {
        _sessionsByCallerCallId.TryRemove(session.CallerCallId, out _);
        if (session.CalleeCallId != null)
            _sessionsByCalleeCallId.TryRemove(session.CalleeCallId, out _);
        session.State = CallState.Disconnected;
        _logger.LogInformation("会话已移除: {Session}", session);
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
