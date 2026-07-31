using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// SIP Trunk 管理器接口
/// 负责向运营商 SIP 服务器发起出站注册并保持注册活跃
/// 提供路由解析、Digest 认证构建等核心功能
/// </summary>
public interface ITrunkManager
{
    void BindTransport(SIPTransport transport);
    Task StartAllRegistrations();
    (string ip, int port) GetOutboundAddress(SipTrunkConfig trunk);
    SIPEndPoint GetTrunkTransportEP();
    Task SendRequestAsync(SIPEndPoint destination, SIPRequest request);
    SIPAuthorisationDigest BuildManualDigest(string username, string password, string realm, string nonce, string qop, string uri, string method, string opaque);
    (SipTrunkConfig? Trunk, DialRouteRule? Route) ResolveOutboundRoute(string destination);
    DidMapping? ResolveDidMapping(string didNumber);
    CallForwardRule? ResolveForwardRule(string extension, CallForwardType type);
    IEnumerable<TrunkRegistrationState> GetAllTrunkStates();
    TrunkRegistrationState? GetTrunkState(string trunkName);
}
