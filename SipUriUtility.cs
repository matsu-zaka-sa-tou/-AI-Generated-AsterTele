using Microsoft.Extensions.Logging;
using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// SIP URI 工具类
/// 提供 SIP URI 到 SIPEndPoint 的解析
/// 消除项目中2处重复的 ResolveSipUriEndPoint 逻辑
/// </summary>
public static class SipUriUtility
{
    /// <summary>
    /// 将 SIPURI 解析为 SIPEndPoint (支持域名 + 自定义 DNS 服务器)
    /// </summary>
    public static SIPEndPoint ResolveSipUriEndPoint(SIPURI uri, string? dnsServer, ILogger? logger = null)
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

        var ip = DnsResolver.Resolve(host, dnsServer, logger);
        return new SIPEndPoint(SIPProtocolsEnum.udp, ip, port);
    }
}
