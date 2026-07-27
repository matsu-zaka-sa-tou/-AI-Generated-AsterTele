using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SIPSorcery.SIP;
using SIPSorcery.SIP.App;

namespace AsterTele;

/// <summary>
/// SIP Trunk 注册状态
/// </summary>
public class TrunkRegistrationState
{
    public string TrunkName { get; set; } = string.Empty;
    public bool IsRegistered { get; set; }
    public DateTime? LastRegisteredAt { get; set; }
    public DateTime? LastRefreshAt { get; set; }
    public int RegisterExpiry { get; set; }
    public string? CallId { get; set; }
    public int CSeq { get; set; }
    public string? Opaque { get; set; }
    public string? Nonce { get; set; }
    public string? FromTag { get; set; }
    public int RegisterAttempts { get; set; }

    public override string ToString() =>
        $"[{TrunkName}] Registered={IsRegistered}, LastAt={LastRegisteredAt:HH:mm:ss}, Expiry={RegisterExpiry}s";
}

/// <summary>
/// SIP Trunk 管理器
/// 负责向运营商 SIP 服务器发起出站注册并保持注册活跃
/// 使用独立的 SIPTransport (随机端口) 避免 NAT 端口转发回环
/// </summary>
public class SipTrunkManager
{
    private readonly ILogger<SipTrunkManager> _logger;
    private readonly SipOptions _options;
    private readonly Dictionary<string, TrunkRegistrationState> _trunkStates = new();

    /// <summary>主 SIP 传输层 (5060, 用于 REGISTER + 外呼 INVITE)</summary>
    private SIPTransport? _mainTransport;

    private Timer? _refreshTimer;

    public SipTrunkManager(ILogger<SipTrunkManager> logger, IOptions<SipOptions> options)
    {
        _logger = logger;
        _options = options.Value;

        foreach (var trunk in _options.Trunks.Where(t => t.Enabled))
        {
            _trunkStates[trunk.Name] = new TrunkRegistrationState
            {
                TrunkName = trunk.Name,
                RegisterExpiry = trunk.RegisterExpiry,
                CSeq = 1
            };
            _logger.LogInformation("加载 SIP Trunk: {Name} → {Registrar}", trunk.Name, trunk.Registrar);
        }
    }

    /// <summary>
    /// 绑定主 SIP 传输层 (5060, 用于 REGISTER + 外呼 INVITE)
    /// 注册响应和外呼 INVITE 响应都通过主 transport 接收
    /// 关键: 外呼 INVITE 必须走主 transport (5060), 因为 REGISTER Contact 声明的端口是 5060
    /// 运营商基于 REGISTER Contact 端口路由 INVITE 的响应, 端口不一致会导致响应丢失
    /// </summary>
    public void BindTransport(SIPTransport mainTransport)
    {
        _mainTransport = mainTransport;

        // 注册响应事件 (主 transport 收到 401/200 OK 等)
        _mainTransport.SIPTransportResponseReceived += OnTrunkResponse;

        // 注意: 不再使用独立 trunk transport
        // 之前用随机端口导致外呼 INVITE Contact 端口(60039) != REGISTER Contact 端口(5060)
        // 运营商无法正确路由 INVITE 响应, 导致外呼无响应
        // MicroSIP 成功的关键: REGISTER 和 INVITE 用同一端口
        _logger.LogInformation("Trunk 外呼将使用主传输层 (端口 {Port})", _options.SipPort);

        // 启动定时刷新 (每 60 秒检查一次)
        _refreshTimer = new Timer(async _ => await RefreshAllRegistrations(),
            null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(60));
    }

    /// <summary>
    /// 解析指定 Trunk 的出站对外地址 (Contact/Via 头)
    /// 优先级: Trunk.OutboundAddress > 全局 AdvertisedAddress > 本机 IP
    /// </summary>
    private (string ip, int port) ResolveOutboundAddress(SipTrunkConfig trunk)
    {
        // 1. Trunk 级别配置 (运营商侧看到的公网 IP)
        if (!string.IsNullOrEmpty(trunk.OutboundAddress))
        {
            return (trunk.OutboundAddress, trunk.OutboundPort ?? _options.SipPort);
        }

        // 2. 全局 AdvertisedAddress (内网 NAT 场景下的路由器 IP)
        if (!string.IsNullOrEmpty(_options.AdvertisedAddress))
        {
            return (_options.AdvertisedAddress, _options.AdvertisedPort ?? _options.SipPort);
        }

        // 3. 回退到本机 IP
        var localIp = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                      && ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                      && !System.Net.IPAddress.IsLoopback(ua.Address))
            .Select(ua => ua.Address.ToString())
            .FirstOrDefault();

        return (localIp ?? "127.0.0.1", _options.SipPort);
    }

    /// <summary>
    /// 解析指定 Trunk 的出站对外地址 (公开版本, 供 SipSoftSwitch 外呼 INVITE 使用)
    /// </summary>
    public (string ip, int port) GetOutboundAddress(SipTrunkConfig trunk) => ResolveOutboundAddress(trunk);

    /// <summary>
    /// 获取主传输层的监听端点 (用于外呼 INVITE 的 Contact/Via 头)
    /// 外呼 INVITE 必须走主 transport (5060), 与 REGISTER Contact 端口一致
    /// </summary>
    public SIPEndPoint GetTrunkTransportEP()
    {
        if (_mainTransport == null)
            throw new InvalidOperationException("主传输层未初始化");
        return _mainTransport.GetSIPChannels().First().ListeningSIPEndPoint;
    }

    /// <summary>
    /// 通过主传输层发送外呼 INVITE (5060 端口出口, 与 REGISTER Contact 端口一致)
    /// </summary>
    public async Task SendRequestAsync(SIPEndPoint destination, SIPRequest request)
    {
        if (_mainTransport == null)
            throw new InvalidOperationException("主传输层未初始化");
        await _mainTransport.SendRequestAsync(destination, request);
    }

    /// <summary>
    /// 注册外呼 INVITE 响应事件 (现在通过主 transport 接收)
    /// 注意: SipSoftSwitch 的主 transport 已注册了 OnSipResponseReceived
    /// 外呼 INVITE 的响应 (180/200 OK 等) 由 SipSoftSwitch.OnSipResponseReceived 统一处理
    /// </summary>
    public void RegisterOutboundResponseHandler(SIPTransportResponseAsyncDelegate handler)
    {
        // 不再需要单独注册, 主 transport 的响应事件由 SipSoftSwitch 统一处理
        // 保留此方法以保持 API 兼容, 但不再添加额外的事件处理器
        _logger.LogDebug("外呼 INVITE 响应已由主 transport 的 SipSoftSwitch 处理, 无需额外注册");
    }

    /// <summary>
    /// 启动所有 Trunk 的出站注册
    /// </summary>
    public async Task StartAllRegistrations()
    {
        foreach (var trunk in _options.Trunks.Where(t => t.Enabled))
        {
            await RegisterTrunk(trunk);
        }
    }

    /// <summary>
    /// 向运营商发 REGISTER (初始注册, 不带认证)
    /// </summary>
    private async Task RegisterTrunk(SipTrunkConfig trunk)
    {
        if (_mainTransport == null)
        {
            _logger.LogWarning("主 SIP Transport 未绑定, 无法注册 Trunk {Name}", trunk.Name);
            return;
        }

        var state = _trunkStates[trunk.Name];
        state.RegisterAttempts++;

        // 每次 REGISTER 事务使用相同的 CallId + FromTag (RFC 3261)
        // 如果还没有, 先生成并缓存
        state.CallId ??= CallProperties.CreateNewCallId();
        state.FromTag ??= CallProperties.CreateNewCallId()[..8];
        state.CSeq++;

        try
        {
            // 解析运营商地址 (支持域名, DNS 解析)
            var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
                ? trunk.Registrar : $"sip:{trunk.Registrar}");
            var registrarEP = ResolveSipUriEndPoint(registrarUri);

            // IMS 场景下各头字段 (对齐 MicroSIP 抓包):
            //   Request-URI = client_uri host (sip:cq.ctcims.cn) — IMS 域, 非 SIP 代理主机
            //   Route       = <sip:bac26.cq.ctcims.cn;lr> — 强制下一跳到 SIP 代理
            //   To          = client_uri  (sip:+862356767450@cq.ctcims.cn)
            //   From        = from_user@from_domain (带 display name + tag)
            //   Contact     = contact_user@localIP:localPort;ob (带 display name)
            //   Via         = SIP/2.0/UDP localIP:localPort (内网 IP, 运营商通过 received/rport 记录公网地址)

        var (fromUser, fromDomain) = ResolveFromParts(trunk);
        var clientUri = ResolveClientUri(trunk, registrarUri);

        // 解析此 Trunk 的出站地址
        // Via sent-by 使用内网 IP + 实际监听端口 (MicroSIP 抓包确认: 运营商通过 received/rport 记录 NAT 后地址)
        // Contact/SDP 使用 OutboundAddress (运营商侧看到的 SNAT 后公网 IP)
        var (outboundIp, outboundPort) = ResolveOutboundAddress(trunk);

        // Via sent-by: 使用本机内网 IP + 主 transport 监听端口 (5060)
        // MicroSIP 抓包: Via: SIP/2.0/UDP 192.168.40.140:54625 (内网 IP)
        // 运营商收到后自动添加 received=172.48.242.167;rport=54625 记录 NAT 后地址
        var mainChannelPort = _mainTransport?.GetSIPChannels().FirstOrDefault()?.ListeningSIPEndPoint.Port ?? _options.SipPort;
        var localIP = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                      && ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                      && !System.Net.IPAddress.IsLoopback(ua.Address)
                      && !ua.Address.Equals(System.Net.IPAddress.Any))
            .Select(ua => ua.Address.ToString())
            .FirstOrDefault() ?? "127.0.0.1";

        // 构建 REGISTER 请求
        // Request-URI: MicroSIP 抓包为 sip:cq.ctcims.cn (仅 IMS 域, 无 user 部分!)
        var registerRequestUri = SIPURI.ParseSIPURI($"sip:{clientUri.HostAddress}");
        var registerRequest = SIPRequest.GetRequest(SIPMethodsEnum.REGISTER, registerRequestUri);

        // Route 头: 强制下一跳为 SIP 代理 (MicroSIP 抓包: Route: <sip:bac26.cq.ctcims.cn;lr> — 无 :5060)
        var routeUri = SIPURI.ParseSIPURI($"sip:{registrarUri.HostAddress}");
        registerRequest.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

        // Display name: MicroSIP 抓包使用 "+862356767450@cq.ctcims.cn" 格式
        var displayName = $"{fromUser}@{clientUri.HostAddress}";

        // From: 使用缓存的 FromTag (同一注册事务内保持一致) + display name
        registerRequest.Header.From = new SIPFromHeader(displayName,
            new SIPURI(fromUser, fromDomain, null, SIPSchemesEnum.sip),
            state.FromTag);
        registerRequest.Header.To = new SIPToHeader(displayName, clientUri, null);
        registerRequest.Header.CallId = state.CallId;
        registerRequest.Header.CSeq = state.CSeq;
        registerRequest.Header.Expires = trunk.RegisterExpiry;

        // Contact: MicroSIP 抓包使用本地 IP + 端口 (192.168.40.140:54625;ob)
        // 运营商通过 received/rport 记录 NAT 后的公网地址, 不依赖 Contact 路由
        var contactUser = !string.IsNullOrEmpty(trunk.ContactUser) ? trunk.ContactUser : fromUser;
        var contactHost = $"{localIP}:{mainChannelPort}";
        var contactUri = new SIPURI(contactUser, contactHost, null, SIPSchemesEnum.sip);
        contactUri.Parameters.Set("ob", null); // ;ob 参数 (MicroSIP 抓包确认)
        registerRequest.Header.Contact = [new SIPContactHeader(displayName, contactUri)];

        // === 修正 Via 头: sent-by 使用内网 IP + 实际监听端口 ===
        // MicroSIP 抓包: Via: SIP/2.0/UDP 192.168.40.140:54625 (内网 IP)
        // 运营商自动通过 received/rport 参数记录 NAT 后的公网 IP 端口
        FixViaHeader(registerRequest, localIP, mainChannelPort);

        // 如果有缓存的 nonce (之前成功注册过), 携带 Authorization 头避免 401 往返
        if (!string.IsNullOrEmpty(state.Nonce))
        {
            AddAuthorizationHeader(registerRequest, trunk, state);
        }

        _logger.LogInformation("向运营商 {Registrar} 发送 REGISTER (Trunk={Name}, 尝试 #{Attempt}, CSeq={CSeq}, " +
            "From={From}, To={To}, Contact={Contact}, OutboundIP={OutboundIP}, CallId={CallId})",
            trunk.Registrar, trunk.Name, state.RegisterAttempts, state.CSeq,
            registerRequest.Header.From.FromURI, registerRequest.Header.To.ToURI,
            contactUri, $"{localIP}:{mainChannelPort}", state.CallId);

            // 打印完整 REGISTER 报文 (Info 级别, 便于排查 IMS 注册问题)
            _logger.LogInformation("REGISTER 报文:\n{Packet}", registerRequest.ToString());

            // 通过主 transport 发送 (走 5060, 运营商 401 响应也回到 5060)
            if (_mainTransport != null)
                await _mainTransport.SendRequestAsync(registrarEP, registerRequest);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "向 Trunk {Name} 发送 REGISTER 失败", trunk.Name);
        }
    }

    /// <summary>
    /// 处理 Trunk 注册响应
    /// </summary>
    private async Task OnTrunkResponse(SIPEndPoint localEP, SIPEndPoint remoteEP, SIPResponse response)
    {
        // 只处理 REGISTER 相关的响应
        if (response.Header.CSeqMethod != SIPMethodsEnum.REGISTER)
            return;

        // 查找匹配的 Trunk (通过 Call-ID 关联)
        var trunk = _options.Trunks.FirstOrDefault(t =>
            t.Enabled && _trunkStates.TryGetValue(t.Name, out var s) && s.CallId == response.Header.CallId);

        // 兜底: 通过 From 头的 Host 匹配
        if (trunk == null)
        {
            trunk = _options.Trunks.FirstOrDefault(t =>
                t.Enabled && response.Header.From.FromURI.Host.Contains(
                    t.Registrar.Replace("sip:", "").Split(':')[0]));
        }

        if (trunk == null)
            return; // 不是 Trunk 注册的响应

        var state = _trunkStates[trunk.Name];

        _logger.LogInformation("Trunk {Name} 收到响应: {Status} {Reason} (CallId={CallId}, CSeq={CSeq})",
            trunk.Name, response.Status, response.ReasonPhrase, response.Header.CallId, response.Header.CSeq);

        switch (response.Status)
        {
            case SIPResponseStatusCodesEnum.Ok:
                state.IsRegistered = true;
                state.LastRegisteredAt = DateTime.UtcNow;
                var contactHeader = response.Header.Contact.FirstOrDefault();
                if (contactHeader != null && contactHeader.Expires > 0)
                    state.RegisterExpiry = (int)contactHeader.Expires;
                _logger.LogInformation("Trunk {Name} 注册成功! 过期={Expiry}s", trunk.Name, state.RegisterExpiry);
                break;

            case SIPResponseStatusCodesEnum.Unauthorised:
                // 401 挑战 — 携带认证信息重发 REGISTER
                _logger.LogInformation("Trunk {Name} 收到 401 挑战, 重新认证 (CallId={CallId})", trunk.Name, state.CallId);
                await HandleTrunkAuthChallenge(trunk, response, remoteEP);
                break;

            case SIPResponseStatusCodesEnum.Forbidden:
                _logger.LogError("Trunk {Name} 注册被拒绝 (403 Forbidden): {Reason}",
                    trunk.Name, response.ReasonPhrase);
                // 打印 403 完整响应报文, 含运营商可能返回的失败原因
                _logger.LogInformation("403 响应报文:\n{Packet}", response.ToString());
                break;

            case SIPResponseStatusCodesEnum.NotFound:
                _logger.LogWarning("Trunk {Name} 注册响应: 404 NotFound (可能是回环或账号不存在)", trunk.Name);
                break;

            case SIPResponseStatusCodesEnum.ServiceUnavailable:
                _logger.LogWarning("Trunk {Name} 注册响应: 503 Service Unavailable (CallId={CallId}, " +
                    "可能原因: Contact/Via地址运营商无法路由, 认证格式错误, 或运营商服务器暂时不可用)",
                    trunk.Name, state.CallId);
                // 打印运营商返回的完整响应 (含可能的原因描述)
                _logger.LogInformation("503 响应报文:\n{Packet}", response.ToString());
                break;

            default:
                _logger.LogWarning("Trunk {Name} 注册响应: {Status} {Reason}",
                    trunk.Name, response.Status, response.ReasonPhrase);
                break;
        }
    }

    /// <summary>
    /// 处理运营商 401 挑战, 携带 Digest 认证重发 REGISTER
    /// 关键: 使用相同的 CallId + FromTag (同一注册事务), CSeq +1
    /// </summary>
    private async Task HandleTrunkAuthChallenge(SipTrunkConfig trunk, SIPResponse challengeResponse, SIPEndPoint registrarEP)
    {
        if (_mainTransport == null) return;

        var authHeaders = challengeResponse.Header.AuthenticationHeaders;
        if (authHeaders == null || authHeaders.Count == 0)
        {
            _logger.LogWarning("Trunk {Name} 401 响应无 WWW-Authenticate 头", trunk.Name);
            return;
        }

        var authDigestRaw = authHeaders[0].SIPDigest;
        if (authDigestRaw == null)
        {
            _logger.LogWarning("Trunk {Name} 401 响应无法解析 Digest", trunk.Name);
            return;
        }

        _logger.LogInformation("401 Digest 参数: Realm={Realm}, Nonce={Nonce}, Qop={Qop}, Opaque={Opaque}, Algorithm={Algo}, URI={URI}",
            authDigestRaw.Realm,
            authDigestRaw.Nonce?[..Math.Min(12, authDigestRaw.Nonce.Length)],
            authDigestRaw.Qop ?? "(null)",
            authDigestRaw.Opaque?[..Math.Min(8, authDigestRaw.Opaque.Length)],
            authDigestRaw.DigestAlgorithm,
            authDigestRaw.URI ?? "(null)");

        var state = _trunkStates[trunk.Name];

        // 缓存 nonce 供后续刷新使用
        state.Nonce = authDigestRaw.Nonce;
        state.Opaque = authDigestRaw.Opaque;

        // CSeq 递增 (401 后重发必须比上次 +1)
        state.CSeq++;

        // 解析此 Trunk 的出站地址
        var (outboundIp, outboundPort) = ResolveOutboundAddress(trunk);

        // Via sent-by: 使用内网 IP + 主 transport 监听端口
        var mainChannelPort = _mainTransport?.GetSIPChannels().FirstOrDefault()?.ListeningSIPEndPoint.Port ?? _options.SipPort;
        var localIP = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                      && ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                      && !System.Net.IPAddress.IsLoopback(ua.Address)
                      && !ua.Address.Equals(System.Net.IPAddress.Any))
            .Select(ua => ua.Address.ToString())
            .FirstOrDefault() ?? "127.0.0.1";

        // 构建 REGISTER 请求 (带认证)
        // 关键: 使用同一个 CallId + FromTag, 这是同一注册事务!
        // Request-URI 使用 ClientUri 的 Host 部分 (IMS 域, 如 cq.ctcims.cn)
        var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
            ? trunk.Registrar : $"sip:{trunk.Registrar}");

        var (fromUser, fromDomain) = ResolveFromParts(trunk);
        var clientUri = ResolveClientUri(trunk, registrarUri);
        var contactUser = !string.IsNullOrEmpty(trunk.ContactUser) ? trunk.ContactUser : fromUser;

        // Request-URI: 仅 IMS 域, 无 user 部分 (MicroSIP: sip:cq.ctcims.cn)
        var registerRequestUri = SIPURI.ParseSIPURI($"sip:{clientUri.HostAddress}");
        var registerRequest = SIPRequest.GetRequest(SIPMethodsEnum.REGISTER, registerRequestUri);

        // Route 头: 无 :5060 端口 (MicroSIP: <sip:bac26.cq.ctcims.cn;lr>)
        var routeUri = SIPURI.ParseSIPURI($"sip:{registrarUri.HostAddress}");
        registerRequest.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

        // Display name
        var displayName = $"{fromUser}@{clientUri.HostAddress}";

        // 使用缓存的 FromTag (与第一次 REGISTER 一致!)
        registerRequest.Header.From = new SIPFromHeader(displayName,
            new SIPURI(fromUser, fromDomain, null, SIPSchemesEnum.sip),
            state.FromTag);
        registerRequest.Header.To = new SIPToHeader(displayName, clientUri, null);
        registerRequest.Header.CallId = state.CallId;
        registerRequest.Header.CSeq = state.CSeq;
        registerRequest.Header.Expires = trunk.RegisterExpiry;

        // Contact: 使用本地 IP + 端口 (MicroSIP 抓包: 192.168.40.140:54625;ob)
        var contactHost = $"{localIP}:{mainChannelPort}";
        var contactUri = new SIPURI(contactUser, contactHost, null, SIPSchemesEnum.sip);
        contactUri.Parameters.Set("ob", null);
        registerRequest.Header.Contact = [new SIPContactHeader(displayName, contactUri)];

        // 修正 Via 头: sent-by 使用内网 IP + 实际监听端口
        FixViaHeader(registerRequest, localIP, mainChannelPort);

        // === Digest 认证 ===
        // SIPSorcery 10.0.12 bug: SetCredentials() 不触发 GetDigest() 计算
        // 必须手动计算 MD5 Digest Response 并设置 Cnonce/NonceCount
        // Authorization URI 使用 ClientUri 的 Host 部分 (IMS 域, 如 sip:cq.ctcims.cn)
        var authUri = $"sip:{clientUri.HostAddress}";
        var computedDigest = BuildManualDigest(
            trunk.Username, trunk.Password,
            !string.IsNullOrEmpty(trunk.Realm) ? trunk.Realm : authDigestRaw.Realm ?? "",
            authDigestRaw.Nonce ?? "", authDigestRaw.Qop ?? "auth",
            authUri,
            SIPMethodsEnum.REGISTER.ToString(),
            authDigestRaw.Opaque ?? "");

        var authHeader = new SIPAuthenticationHeader(computedDigest);
        registerRequest.Header.AuthenticationHeaders.Add(authHeader);

        _logger.LogInformation("Digest 认证参数: HA1={HA1}, Response={Response}, Cnonce={Cnonce}, NC={NC}, " +
            "Realm={Realm}, URI={URI}, Qop={Qop}",
            computedDigest.HA1, computedDigest.Response, computedDigest.Cnonce, computedDigest.NonceCount,
            computedDigest.Realm, computedDigest.URI, computedDigest.Qop);

        _logger.LogInformation("向运营商 {Registrar} 发送带认证的 REGISTER (Trunk={Name}, CallId={CallId}, " +
            "CSeq={CSeq}, Contact={Contact}, OutboundIP={OutboundIP})",
            trunk.Registrar, trunk.Name, state.CallId, state.CSeq, contactUri,
            $"{localIP}:{mainChannelPort}");

        // 打印完整带认证 REGISTER 报文 (Info 级别, 便于排查)
        _logger.LogInformation("带认证 REGISTER 报文:\n{Packet}", registerRequest.ToString());

        if (_mainTransport != null)
            await _mainTransport.SendRequestAsync(registrarEP, registerRequest);
    }

    /// <summary>
    /// 为 REGISTER 请求添加 Authorization 头 (用于带缓存的 nonce 刷新注册)
    /// 使用手动 Digest 计算, 绕过 SIPSorcery 10.0.12 SetCredentials bug
    /// </summary>
    private void AddAuthorizationHeader(SIPRequest request, SipTrunkConfig trunk, TrunkRegistrationState state)
    {
        if (string.IsNullOrEmpty(state.Nonce))
            return;

        var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
            ? trunk.Registrar : $"sip:{trunk.Registrar}");

        // 授权 URI 使用 ClientUri 的 Host 部分 (IMS 域, 如 sip:cq.ctcims.cn)
        var clientUriForAuth = ResolveClientUri(trunk, SIPURI.ParseSIPURI(
            trunk.Registrar.StartsWith("sip:") ? trunk.Registrar : $"sip:{trunk.Registrar}"));
        var authUri = $"sip:{clientUriForAuth.HostAddress}";
        // Realm: 优先用 401 返回的 realm (缓存), 否则用配置的 realm
        // 注意: trunk.Registrar 是完整 SIP URI (如 sip:bac26.cq.ctcims.cn:5060), 不适合做 realm
        // MicroSIP 抓包: realm="cq.ctcims.cn" (IMS 域)
        var realm = !string.IsNullOrEmpty(trunk.Realm) ? trunk.Realm
            : !string.IsNullOrEmpty(state.Opaque) ? $"{clientUriForAuth.HostAddress}" /* 用 IMS 域作 realm */
            : trunk.Registrar;
        var computedDigest = BuildManualDigest(
            trunk.Username, trunk.Password,
            realm, state.Nonce ?? "", "auth",
            authUri,
            SIPMethodsEnum.REGISTER.ToString(),
            state.Opaque ?? "");

        var authHeader = new SIPAuthenticationHeader(computedDigest);
        request.Header.AuthenticationHeaders.Add(authHeader);

        _logger.LogDebug("REGISTER 携带缓存的 Authorization (nonce={Nonce}, Response={Response})",
            state.Nonce?[..Math.Min(8, state.Nonce.Length)], computedDigest.Response?[..Math.Min(8, computedDigest.Response.Length)]);
    }

    /// <summary>
    /// 手动构建完整的 SIPAuthorisationDigest (绕过 SIPSorcery 10.0.12 SetCredentials bug)
    /// SetCredentials() 在 qop=auth 时不计算 Response/Cnonce/NonceCount
    /// 此方法手动计算 MD5 Digest 并设置所有字段
    /// </summary>
    public SIPAuthorisationDigest BuildManualDigest(
        string username, string password, string realm,
        string nonce, string qop, string uri, string method,
        string opaque)
    {
        var auth = new SIPAuthorisationDigest(SIPAuthorisationHeadersEnum.Authorize, DigestAlgorithmsEnum.MD5);
        auth.Realm = realm;
        auth.Nonce = nonce;
        auth.Qop = qop;
        auth.URI = uri;
        auth.Opaque = opaque;
        auth.DigestAlgorithm = DigestAlgorithmsEnum.MD5;
        auth.Username = username;
        auth.Password = password;
        auth.RequestType = method;

        // 手动计算 MD5 Digest
        var ha1 = ComputeMD5($"{username}:{realm}:{password}");
        var ha2 = ComputeMD5($"{method}:{uri}");
        auth.HA1 = ha1;

        if (!string.IsNullOrEmpty(qop))
        {
            // qop=auth: Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            var cnonce = GenerateCnonce();
            var nc = 1;
            var ncStr = nc.ToString("D8"); // "00000001"
            var response = ComputeMD5($"{ha1}:{nonce}:{ncStr}:{cnonce}:{qop}:{ha2}");

            auth.Cnonce = cnonce;
            auth.NonceCount = nc;
            auth.Response = response;
        }
        else
        {
            // 无 qop: Response = MD5(HA1:nonce:HA2)
            var response = ComputeMD5($"{ha1}:{nonce}:{ha2}");
            auth.Response = response;
        }

        return auth;
    }

    /// <summary>
    /// 计算 MD5 哈希的十六进制字符串
    /// </summary>
    private static string ComputeMD5(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// 生成随机 Cnonce (16 位十六进制)
    /// </summary>
    private static string GenerateCnonce()
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
    }

    /// <summary>
    /// 修正 Via 头: 设置 sent-by 主机地址 (Host/Port)
    /// SIPSorcery SIPViaHeader.Host/Port 是 Via 行渲染的 "sent-by" 地址
    /// 运营商需要看到 OutboundAddress 才能正确路由响应回包
    /// 
    /// 注意: Host/Port 才是渲染到报文 Via 行的地址 (如 "Via: SIP/2.0/UDP 172.48.242.167:5060")
    /// ReceivedFromIPAddress/ReceivedFromPort 只是 ;received/;rport 参数, 不影响 sent-by
    /// </summary>
    private void FixViaHeader(SIPRequest request, string outboundIp, int outboundPort)
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

            // 替换 sent-by 主机地址 (这是渲染到报文中的地址)
            // 运营商无法路由内网/无效地址, 必须替换为 OutboundAddress
            bool needFix = string.IsNullOrEmpty(oldHost)
                || !System.Net.IPAddress.TryParse(oldHost, out var hostIP)
                || hostIP.Equals(System.Net.IPAddress.Any)            // 0.0.0.0
                || hostIP.Equals(System.Net.IPAddress.Loopback)       // 127.0.0.1
                || hostIP.IsIPv6LinkLocal
                || IsPrivateIPAddress(hostIP);                         // RFC 1918 私网;

            if (needFix)
            {
                via.Host = outboundIp;
                via.Port = outboundPort;
                _logger.LogInformation("修正 Via sent-by: {OldHost}:{OldPort} → {NewHost}:{NewPort}",
                    oldHost, oldPort, outboundIp, outboundPort);
            }
        }
    }

    /// <summary>
    /// 判断是否为 RFC 1918 私网地址 (运营商不可路由)
    /// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    /// </summary>
    private static bool IsPrivateIPAddress(System.Net.IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10                                              // 10.0.0.0/8
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)      // 172.16.0.0/12
            || (bytes[0] == 192 && bytes[1] == 168);                       // 192.168.0.0/16
    }

    /// <summary>
    /// 定时刷新所有 Trunk 注册
    /// 在过期前 120 秒触发刷新
    /// </summary>
    private async Task RefreshAllRegistrations()
    {
        foreach (var trunk in _options.Trunks.Where(t => t.Enabled))
        {
            var state = _trunkStates[trunk.Name];
            if (state.LastRegisteredAt == null)
            {
                // 尚未注册成功, 重新尝试
                await RegisterTrunk(trunk);
                continue;
            }

            var age = DateTime.UtcNow - state.LastRegisteredAt.Value;
            var remaining = state.RegisterExpiry - (int)age.TotalSeconds;

            if (remaining < 120)
            {
                _logger.LogInformation("Trunk {Name} 注册即将过期 (剩余 {Remaining}s), 刷新注册",
                    trunk.Name, remaining);
                // 刷新注册: 保持 CallId + FromTag, 重置 CSeq
                state.CSeq = 0;
                state.RegisterAttempts = 0;
                await RegisterTrunk(trunk);
            }
        }
    }

    /// <summary>
    /// 获取指定 Trunk 的注册状态
    /// </summary>
    public TrunkRegistrationState? GetTrunkState(string trunkName)
    {
        return _trunkStates.TryGetValue(trunkName, out var s) ? s : null;
    }

    /// <summary>
    /// 获取所有 Trunk 状态
    /// </summary>
    public IEnumerable<TrunkRegistrationState> GetAllTrunkStates() => _trunkStates.Values;

    /// <summary>
    /// 根据拨号前缀查找匹配的路由规则和 Trunk
    /// </summary>
    public (SipTrunkConfig? Trunk, DialRouteRule? Route) ResolveOutboundRoute(string destination)
    {
        foreach (var route in _options.DialRoutes.Where(r => r.Enabled))
        {
            if (destination.StartsWith(route.Prefix))
            {
                var trunk = _options.Trunks.FirstOrDefault(t => t.Name == route.TrunkName && t.Enabled);
                return (trunk, route);
            }
        }
        return (null, null);
    }

    /// <summary>
    /// 根据 DID 号码查找入站映射
    /// </summary>
    public DidMapping? ResolveDidMapping(string didNumber)
    {
        return _options.DidMappings.FirstOrDefault(d => d.DidNumber == didNumber);
    }

    /// <summary>
    /// 根据分机号查找生效的呼叫转移规则
    /// </summary>
    public CallForwardRule? ResolveForwardRule(string extension, CallForwardType type)
    {
        return _options.CallForwardRules.FirstOrDefault(r =>
            r.Enabled && r.Extension == extension && r.ForwardType == type);
    }

    public void Dispose()
    {
        _refreshTimer?.Dispose();
        // 不再需要清理 trunk transport (已废弃)
    }

    /// <summary>
    /// 将 SIPURI 解析为 SIPEndPoint (支持域名 DNS 解析)
    /// </summary>
    private SIPEndPoint ResolveSipUriEndPoint(SIPURI uri)
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

        var ip = DnsResolver.Resolve(host, _options.DnsServer, _logger);
        return new SIPEndPoint(SIPProtocolsEnum.udp, ip, port);
    }

    /// <summary>
    /// 解析 From 头的 user 和 domain
    /// IMS 场景: from_user + from_domain 可分别指定
    /// 默认: Username 的 @ 前半部分 + Registrar 的 Host
    /// </summary>
    private (string user, string domain) ResolveFromParts(SipTrunkConfig trunk)
    {
        var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
            ? trunk.Registrar : $"sip:{trunk.Registrar}");

        // from_user: 优先用配置, 否则取 Username 的 @ 前半部分
        var fromUser = trunk.FromUser;
        if (string.IsNullOrEmpty(fromUser))
        {
            var atIdx = trunk.Username.IndexOf('@');
            fromUser = atIdx > 0 ? trunk.Username[..atIdx] : trunk.Username;
        }

        // from_domain: 优先用配置, 否则用 Registrar 的 Host
        var fromDomain = !string.IsNullOrEmpty(trunk.FromDomain)
            ? trunk.FromDomain
            : registrarUri.HostAddress;

        return (fromUser, fromDomain);
    }

    /// <summary>
    /// 解析 To 头的 Client URI (注册身份 AoR)
    /// IMS 场景: client_uri 的域名通常是 IMS 域 (如 cq.ctcims.cn), 不是 SIP 代理主机
    /// 若配置了 ClientUri 则直接解析, 否则用 Username 构造 (user@registrar_host)
    /// </summary>
    private SIPURI ResolveClientUri(SipTrunkConfig trunk, SIPURI registrarUri)
    {
        if (!string.IsNullOrEmpty(trunk.ClientUri))
        {
            return SIPURI.ParseSIPURI(trunk.ClientUri.StartsWith("sip:")
                ? trunk.ClientUri : $"sip:{trunk.ClientUri}");
        }

        // 默认: Username 作为完整 user@domain 放在 registrar host 下
        // 如果 Username 包含 @, 则拆分 user 和 domain
        var atIdx = trunk.Username.IndexOf('@');
        if (atIdx > 0)
        {
            var user = trunk.Username[..atIdx];
            var domain = trunk.Username[(atIdx + 1)..];
            return new SIPURI(user, domain, null, SIPSchemesEnum.sip);
        }

        return new SIPURI(trunk.Username, registrarUri.HostAddress, null, SIPSchemesEnum.sip);
    }
}
