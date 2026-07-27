using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace AsterTele;

/// <summary>
/// DNS 解析器
/// 支持自定义 DNS 服务器 (如内网路由器 192.168.40.1)
/// 通过 UDP 发送标准 DNS A 记录查询, 不依赖系统 DNS 配置
/// </summary>
public static class DnsResolver
{
    /// <summary>
    /// 解析域名为 IP 地址
    /// 优先使用自定义 DNS 服务器, 回退到系统默认 DNS
    /// </summary>
    public static IPAddress Resolve(string host, string? dnsServer, ILogger? logger = null)
    {
        // IP 地址直接返回
        if (IPAddress.TryParse(host, out var directIP))
            return directIP;

        // 尝试自定义 DNS
        if (!string.IsNullOrEmpty(dnsServer) && IPAddress.TryParse(dnsServer, out var dnsIP))
        {
            try
            {
                var ip = QueryARecord(host, dnsIP, 3000);
                logger?.LogInformation("DNS 解析 (自定义 {Server}): {Host} → {IP}", dnsServer, host, ip);
                return ip;
            }
            catch (Exception ex)
            {
                logger?.LogWarning(ex, "自定义 DNS ({Server}) 解析 {Host} 失败, 回退系统 DNS", dnsServer, host);
            }
        }

        // 回退系统 DNS
        logger?.LogInformation("DNS 解析 (系统默认): {Host} → ...", host);
        var addresses = Dns.GetHostAddresses(host);
        var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                   ?? addresses.First();
        logger?.LogInformation("DNS 解析 (系统默认): {Host} → {IP}", host, ipv4);
        return ipv4;
    }

    /// <summary>
    /// 通过 UDP 发送 DNS A 记录查询
    /// 协议: RFC 1035 (极简实现, 仅处理 A 记录)
    /// </summary>
    private static IPAddress QueryARecord(string domain, IPAddress dnsServer, int timeoutMs)
    {
        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = timeoutMs;
        udp.Client.SendTimeout = timeoutMs;

        var dnsEP = new IPEndPoint(dnsServer, 53);

        // 构建 DNS 查询包
        // Header: ID(2) + Flags(2) + QDCount(2) + ANCount(2) + NSCount(2) + ARCount(2) = 12 bytes
        var queryId = (ushort)Random.Shared.Next(1, 0xFFFF);
        var packet = new List<byte>();

        // Header
        packet.AddRange(BitConverter.GetBytes(queryId).Reverse());      // ID (big-endian)
        packet.AddRange(new byte[] { 0x01, 0x00 });                      // Flags: standard query, recursion desired
        packet.AddRange(new byte[] { 0x00, 0x01 });                      // QDCount: 1 question
        packet.AddRange(new byte[] { 0x00, 0x00 });                      // ANCount
        packet.AddRange(new byte[] { 0x00, 0x00 });                      // NSCount
        packet.AddRange(new byte[] { 0x00, 0x00 });                      // ARCount

        // Question section: QNAME + QTYPE(2) + QCLASS(2)
        foreach (var label in domain.Split('.'))
        {
            packet.Add((byte)label.Length);
            packet.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        packet.Add(0x00);                                                // Root label (end of QNAME)
        packet.AddRange(new byte[] { 0x00, 0x01 });                      // QTYPE: A (1)
        packet.AddRange(new byte[] { 0x00, 0x01 });                      // QCLASS: IN (1)

        // 发送查询
        var queryBytes = packet.ToArray();
        udp.Send(queryBytes, queryBytes.Length, dnsEP);

        // 接收响应
        var receiveEP = new IPEndPoint(IPAddress.Any, 0);
        var response = udp.Receive(ref receiveEP);

        if (response.Length < 12)
            throw new Exception("DNS 响应包过短");

        // 检查响应 ID 匹配
        var respId = (ushort)((response[0] << 8) | response[1]);
        if (respId != queryId)
            throw new Exception($"DNS 响应 ID 不匹配 (期望 {queryId}, 收到 {respId})");

        // 检查响应码 (低 4 位 of byte 3)
        var rcode = response[3] & 0x0F;
        if (rcode != 0)
            throw new Exception($"DNS 响应错误码: {rcode}");

        // 解析 Answer 数量
        var anCount = (response[6] << 8) | response[7];
        if (anCount == 0)
            throw new Exception("DNS 响应无 Answer 记录");

        // 跳过 Question 部分
        var pos = 12;
        while (pos < response.Length && response[pos] != 0)
            pos += response[pos] + 1;
        pos += 5; // null label (1) + QTYPE (2) + QCLASS (2)

        // 遍历 Answer 记录, 找 A 记录
        for (var i = 0; i < anCount && pos < response.Length; i++)
        {
            // 跳过 NAME (可能是压缩指针 0xC0xx)
            if (response[pos] >= 0xC0)
            {
                pos += 2;
            }
            else
            {
                while (pos < response.Length && response[pos] != 0)
                    pos += response[pos] + 1;
                pos++;
            }

            if (pos + 10 > response.Length) break;

            var qtype = (response[pos] << 8) | response[pos + 1];
            // var qclass = (response[pos + 2] << 8) | response[pos + 3];
            var rdLength = (response[pos + 8] << 8) | response[pos + 9];
            pos += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

            if (qtype == 1 && rdLength == 4 && pos + 4 <= response.Length)
            {
                // A 记录: 4 字节 IPv4 地址
                return new IPAddress(response[pos..(pos + 4)]);
            }

            pos += rdLength;
        }

        throw new Exception($"DNS 响应中未找到 A 记录 (Answer={anCount})");
    }
}
