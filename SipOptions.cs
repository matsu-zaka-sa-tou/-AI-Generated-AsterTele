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

    /// <summary>自定义 DNS 服务器 (用于解析 SIP Trunk 域名, 如路由器/内网 DNS)
    /// 若为空则使用系统默认 DNS
    /// </summary>
    public string? DnsServer { get; set; }

    /// <summary>分机列表</summary>
    public List<ExtensionConfig> Extensions { get; set; } = [];

    /// <summary>SIP Trunk 配置列表</summary>
    public List<SipTrunkConfig> Trunks { get; set; } = [];

    /// <summary>拨号路由规则列表</summary>
    public List<DialRouteRule> DialRoutes { get; set; } = [];

    /// <summary>呼叫转移规则列表</summary>
    public List<CallForwardRule> CallForwardRules { get; set; } = [];

    /// <summary>入站 DID 映射列表</summary>
    public List<DidMapping> DidMappings { get; set; } = [];
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

/// <summary>
/// SIP Trunk 配置 (出站注册到运营商)
/// 支持 IMS 场景: ServerUri / ClientUri / FromDomain 可分别指定
/// </summary>
public class SipTrunkConfig
{
    /// <summary>Trunk 名称 (标识)</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>运营商注册服务器地址 (REGISTER 的 Request-URI, 如 sip:bac26.cq.ctcims.cn:5060)</summary>
    /// <remarks>对应 Asterisk pjsip: server_uri</remarks>
    public string Registrar { get; set; } = string.Empty;

    /// <summary>客户端 AoR (To 头的 URI, 如 sip:+862356767450@cq.ctcims.cn)
    /// 在 IMS 场景下, 注册身份的域名 (cq.ctcims.cn) 通常与 Registrar 主机 (bac26.cq.ctcims.cn) 不同
    /// 若为空则使用 Username@Registrar.Host</summary>
    /// <remarks>对应 Asterisk pjsip: client_uri</remarks>
    public string? ClientUri { get; set; }

    /// <summary>From 头域名 (如 bac26.cq.ctcims.cn)
    /// 若为空则使用 Registrar 的 Host</summary>
    /// <remarks>对应 Asterisk pjsip: from_domain</remarks>
    public string? FromDomain { get; set; }

    /// <summary>From 头用户名 (如 +862356767450)
    /// 若为空则使用 Username 的 @ 前半部分</summary>
    /// <remarks>对应 Asterisk pjsip: from_user</remarks>
    public string? FromUser { get; set; }

    /// <summary>Contact 头用户名 (如 +862356767450)
    /// 若为空则使用 FromUser / Username 的 @ 前半部分</summary>
    /// <remarks>对应 Asterisk pjsip: contact_user</remarks>
    public string? ContactUser { get; set; }

    /// <summary>运营商代理地址 (若与 Registrar 不同)</summary>
    public string? Proxy { get; set; }

    /// <summary>
    /// 出站对外地址 (运营商侧看到的本机 IP)
    /// 用于 REGISTER/INVITE 的 Contact 头和 Via 头
    /// 例如路由器 SNAT 后运营商看到 172.48.242.167, 则填此地址
    /// 若为空则回退到全局 AdvertisedAddress 或本机 IP
    /// </summary>
    public string? OutboundAddress { get; set; }

    /// <summary>
    /// 出站对外端口 (配合 OutboundAddress 使用, 默认 5060)
    /// </summary>
    public int? OutboundPort { get; set; }

    /// <summary>认证用户名 (通常包含域名, 如 +862356767450@cq.ctcims.cn)</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>认证密码</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>认证域 (Realm, 通常留空由 401 挑战返回)</summary>
    public string Realm { get; set; } = string.Empty;

    /// <summary>注册过期时间 (秒)</summary>
    public int RegisterExpiry { get; set; } = 1800;

    /// <summary>是否启用</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// 拨号路由规则
/// 根据被叫号码前缀决定路由方式
/// </summary>
public class DialRouteRule
{
    /// <summary>匹配前缀 (例如 "9" 表示拨9外呼)</summary>
    public string Prefix { get; set; } = string.Empty;

    /// <summary>路由目标 Trunk 名称</summary>
    public string TrunkName { get; set; } = string.Empty;

    /// <summary>是否在发送到 Trunk 前剥除前缀</summary>
    public bool StripPrefix { get; set; } = true;

    /// <summary>是否启用</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// 呼叫转移规则
/// </summary>
public class CallForwardRule
{
    /// <summary>源分机号 (对该分机生效)</summary>
    public string Extension { get; set; } = string.Empty;

    /// <summary>转移类型: Unconditional=无条件, Busy=遇忙, NoAnswer=无应答</summary>
    public CallForwardType ForwardType { get; set; } = CallForwardType.Unconditional;

    /// <summary>转移目标 (分机号或外部号码)</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>无应答超时 (秒, 仅 NoAnswer 类型有效)</summary>
    public int NoAnswerTimeout { get; set; } = 15;

    /// <summary>是否启用</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// 呼叫转移类型
/// </summary>
public enum CallForwardType
{
    /// <summary>无条件转移 (所有来话直接转移)</summary>
    Unconditional,

    /// <summary>遇忙转移 (被叫忙时转移)</summary>
    Busy,

    /// <summary>无应答转移 (被叫超时未接时转移)</summary>
    NoAnswer
}

/// <summary>
/// 入站 DID 映射
/// 运营商来话 → 本地分机/IVR
/// </summary>
public class DidMapping
{
    /// <summary>DID 号码 (运营商分配的号码)</summary>
    public string DidNumber { get; set; } = string.Empty;

    /// <summary>映射类型: Direct=直通分机, IVR=二次拨号</summary>
    public DidMappingType MappingType { get; set; } = DidMappingType.Direct;

    /// <summary>目标分机号 (Direct 模式)</summary>
    public string? TargetExtension { get; set; }

    /// <summary>IVR 提示语 (预留, 当前阶段记日志)</summary>
    public string? IvrPrompt { get; set; }

    /// <summary>IVR 拨号前缀 (例如 "8", 用户拨 8xxx)</summary>
    public string? IvrPrefix { get; set; }
}

/// <summary>
/// DID 映射类型
/// </summary>
public enum DidMappingType
{
    /// <summary>直通: 来话直接振铃到指定分机</summary>
    Direct,

    /// <summary>IVR 二次拨号: 播放提示音, 用户拨 8xxx 转到分机</summary>
    IVR
}
