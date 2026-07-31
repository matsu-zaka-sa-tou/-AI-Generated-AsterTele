using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// 呼叫管理器接口
/// 管理所有活跃的 B2BUA 呼叫会话
/// </summary>
public interface ICallManager
{
    CallSession CreateSession(string callerNumber, string calleeNumber, SIPRequest callerInvite, SIPEndPoint callerRemoteEP);
    CallSession? FindByCallerCallId(string callId);
    CallSession? FindByCalleeCallId(string callId);
    CallSession? FindByExtension(string number);
    void RegisterCalleeLeg(CallSession session, SIPRequest calleeInvite, SIPEndPoint calleeRemoteEP);
    void MarkConnected(CallSession session);
    void RemoveSession(CallSession session);
    void UnregisterCalleeLeg(string calleeCallId);
    void RemoveSessionByExtension(string number);
    IEnumerable<CallSession> GetActiveSessions();
}
