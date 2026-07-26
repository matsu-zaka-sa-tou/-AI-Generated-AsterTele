namespace AsterTele;

/// <summary>
/// SIP 软交换配置
/// </summary>
public class SipOptions
{
    public const string SectionName = "Sip";

    /// <summary>监听地址</summary>
    public string ListenAddress { get; set; } = "0.0.0.0";

    /// <summary>SIP 端口 (默认 5060)</summary>
    public int SipPort { get; set; } = 5060;

    /// <summary>对外公布的地址 (NAT/端口转发场景下设为路由器IP, 客户端通过此地址访问服务器)</summary>
    /// <remarks>例如服务器在 192.168.40.102, 但 0.0/16 客户端只能通过路由器 192.168.40.1 端口转发到达, 则设为 192.168.40.1</remarks>
    public string? AdvertisedAddress { get; set; }

    /// <summary>对外公布的端口 (默认与 SipPort 相同)</summary>
    public int? AdvertisedPort { get; set; }

    /// <summary>SIP 认证域</summary>
    public string Realm { get; set; } = "asterisk";

    /// <summary>注册过期时间 (秒)</summary>
    public int RegisterExpiry { get; set; } = 3600;

    /// <summary>分机列表</summary>
    public List<ExtensionConfig> Extensions { get; set; } = [];
}

/// <summary>
/// 分机配置
/// </summary>
public class ExtensionConfig
{
    /// <summary>分机号</summary>
    public string Number { get; set; } = string.Empty;

    /// <summary>密码</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>显示名称</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>拨号计划上下文</summary>
    public string Context { get; set; } = "internal";
}
