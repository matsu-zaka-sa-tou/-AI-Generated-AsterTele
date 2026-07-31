using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// 网络工具类
/// 提供本机IP发现、子网判断、私网IP检测、SIP端点选择等通用网络功能
/// 消除项目中4处重复的 GetLocalIP 逻辑
/// </summary>
public static class NetworkUtility
{
    /// <summary>
    /// 获取本机非回环 IPv4 地址
    /// 用于 Via sent-by / Contact / SDP 中的本地 IP
    /// </summary>
    public static string GetLocalIPv4()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up
                      && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(ua => ua.Address.AddressFamily == AddressFamily.InterNetwork
                      && !IPAddress.IsLoopback(ua.Address)
                      && !ua.Address.Equals(IPAddress.Any))
            .Select(ua => ua.Address.ToString())
            .FirstOrDefault() ?? "127.0.0.1";
    }

    /// <summary>
    /// 判断是否为 RFC 1918 私网地址 (运营商不可路由)
    /// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    /// </summary>
    public static bool IsPrivateIPAddress(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return false;

        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10                                              // 10.0.0.0/8
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)      // 172.16.0.0/12
            || (bytes[0] == 192 && bytes[1] == 168);                       // 192.168.0.0/16
    }

    /// <summary>
    /// 判断两个 IP 是否在同一 /24 子网
    /// 同子网客户端可直接访问服务器 IP, 无需经路由器
    /// </summary>
    public static bool IsSameSubnet(IPAddress a, IPAddress b)
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
    public static SIPEndPoint GetContactEPForClient(SIPEndPoint clientEP, SIPEndPoint localEP, SIPEndPoint advertisedEP, ILogger? logger = null)
    {
        if (localEP != SIPEndPoint.Empty && IsSameSubnet(clientEP.Address, localEP.Address))
        {
            logger?.LogDebug("客户端 {Client} 与服务器同子网, 使用直连地址 {Local}", clientEP.Address, localEP.Address);
            return localEP;
        }
        logger?.LogDebug("客户端 {Client} 跨子网, 使用 NAT 地址 {Adv}", clientEP.Address, advertisedEP.Address);
        return advertisedEP;
    }

    /// <summary>
    /// 判断请求是否来自 SIP Trunk 运营商网络
    /// 通过比对运营商 Registrar 域名解析后的 IP 列表来判断
    /// </summary>
    public static bool IsFromTrunkNetwork(SIPEndPoint remoteEP, SipOptions options, ILogger? logger = null)
    {
        foreach (var trunk in options.Trunks.Where(t => t.Enabled))
        {
            var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
                ? trunk.Registrar : $"sip:{trunk.Registrar}");
            var trunkIP = DnsResolver.Resolve(registrarUri.HostAddress, options.DnsServer, logger);
            if (trunkIP != null && trunkIP.Equals(remoteEP.Address))
                return true;
        }
        return false;
    }

    /// <summary>
    /// 修正 Via 头: 设置 sent-by 主机地址 (Host/Port)
    /// SIPSorcery SIPViaHeader.Host/Port 是 Via 行渲染的 "sent-by" 地址
    /// 运营商需要看到 OutboundAddress 才能正确路由响应回包
    /// </summary>
    public static void FixViaHeader(SIPRequest request, string outboundIp, int outboundPort, ILogger? logger = null)
    {
        if (string.IsNullOrEmpty(outboundIp))
            return;

        var viaList = request.Header.Vias.Via;
        if (viaList == null || viaList.Count == 0)
            return;

        foreach (var via in viaList)
        {
            var oldHost = via.Host ?? "(null)";
            var oldPort = via.Port;

            bool needFix = string.IsNullOrEmpty(oldHost)
                || !IPAddress.TryParse(oldHost, out var hostIP)
                || hostIP.Equals(IPAddress.Any)
                || hostIP.Equals(IPAddress.Loopback)
                || hostIP.IsIPv6LinkLocal
                || IsPrivateIPAddress(hostIP);

            if (needFix)
            {
                via.Host = outboundIp;
                via.Port = outboundPort;
                logger?.LogInformation("修正 Via sent-by: {OldHost}:{OldPort} → {NewHost}:{NewPort}",
                    oldHost, oldPort, outboundIp, outboundPort);
            }
        }
    }
}
