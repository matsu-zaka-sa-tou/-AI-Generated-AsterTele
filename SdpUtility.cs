using System.Text.RegularExpressions;

namespace AsterTele;

/// <summary>
/// SDP 工具类
/// 提供 SDP 报文中 IP 地址替换功能
/// 消除项目中3处重复的正则替换逻辑
/// </summary>
public static class SdpUtility
{
    /// <summary>
    /// 替换 SDP 报文中的 IP 地址 (c= 和 o= 行)
    /// 用于 NAT 场景下将内网 IP 替换为公网 OutboundAddress
    /// </summary>
    public static string ReplaceSdpIpAddress(string sdpBody, string newIp)
    {
        if (string.IsNullOrEmpty(sdpBody) || string.IsNullOrEmpty(newIp))
            return sdpBody;

        var result = Regex.Replace(
            sdpBody,
            @"(c=IN IP4 )(\d+\.\d+\.\d+\.\d+)",
            $"${{1}}{newIp}",
            RegexOptions.Multiline);
        result = Regex.Replace(
            result,
            @"(o=.+IN IP4 )(\d+\.\d+\.\d+\.\d+)",
            $"${{1}}{newIp}",
            RegexOptions.Multiline);
        return result;
    }

    /// <summary>
    /// 替换 SDP 中 m=audio 行的端口号
    /// 用于 RTP 媒体锚定: 将远端的 RTP 端口替换为 AsterTele 本地监听端口
    /// </summary>
    public static string ReplaceSdpMediaPort(string sdpBody, int newPort)
    {
        if (string.IsNullOrEmpty(sdpBody))
            return sdpBody;

        return Regex.Replace(
            sdpBody,
            @"(m=audio )\d+( RTP/AVP)",
            $"m=audio {newPort} RTP/AVP",
            RegexOptions.Multiline);
    }

    /// <summary>
    /// 从 SDP 报文中解析 RTP 端点 (IP + 端口)
    /// </summary>
    /// <returns>(IP地址, 端口号) 如果解析失败返回 null</returns>
    public static (string? Ip, int? Port) ParseRtpEndpoint(string sdpBody)
    {
        if (string.IsNullOrEmpty(sdpBody))
            return (null, null);

        string? ip = null;
        int? port = null;

        var cMatch = Regex.Match(sdpBody, @"c=IN IP4 (\d+\.\d+\.\d+\.\d+)", RegexOptions.Multiline);
        if (cMatch.Success)
            ip = cMatch.Groups[1].Value;

        var mMatch = Regex.Match(sdpBody, @"m=audio (\d+)", RegexOptions.Multiline);
        if (mMatch.Success && int.TryParse(mMatch.Groups[1].Value, out var p))
            port = p;

        return (ip, port);
    }
}
