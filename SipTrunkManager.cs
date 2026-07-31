using System.Collections.Concurrent;
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
public class SipTrunkManager : ITrunkManager
{
    private readonly ILogger<SipTrunkManager> _logger;
    private readonly SipOptions _options;
    private readonly RuntimeOptions _runtime;
    private readonly ConcurrentDictionary<string, TrunkRegistrationState> _trunkStates = new();

    /// <summary>主 SIP 传输层 (5060, 用于 REGISTER + 外呼 INVITE)</summary>
    private SIPTransport? _mainTransport;

    private Timer? _refreshTimer;

    public SipTrunkManager(ILogger<SipTrunkManager> logger, IOptions<SipOptions> options)
    {
        _logger = logger;
        _options = options.Value;
        _runtime = _options.Runtime;

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
    /// </summary>
    public void BindTransport(SIPTransport mainTransport)
    {
        _mainTransport = mainTransport;

        // 注册响应事件 (主 transport 收到 401/200 OK 等)
        _mainTransport.SIPTransportResponseReceived += OnTrunkResponse;

        _logger.LogInformation("Trunk 外呼将使用主传输层 (端口 {Port})", _options.SipPort);

        // 启动定时刷新
        _refreshTimer = new Timer(async _ => await RefreshAllRegistrations(),
            null,
            TimeSpan.FromSeconds(_runtime.TrunkRefreshInitialDelaySeconds),
            TimeSpan.FromSeconds(_runtime.TrunkRefreshIntervalSeconds));
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

        // 3. 回退到本机 IP (使用 NetworkUtility 消除重复)
        var localIp = NetworkUtility.GetLocalIPv4();
        return (localIp, _options.SipPort);
    }

    /// <summary>
    /// 解析指定 Trunk 的出站对外地址 (公开版本, 供 SipSoftSwitch 外呼 INVITE 使用)
    /// </summary>
    public (string ip, int port) GetOutboundAddress(SipTrunkConfig trunk) => ResolveOutboundAddress(trunk);

    /// <summary>
    /// 获取主传输层的监听端点 (用于外呼 INVITE 的 Contact/Via 头)
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
        state.CallId ??= CallProperties.CreateNewCallId();
        state.FromTag ??= CallProperties.CreateNewCallId()[..8];
        state.CSeq++;

        try
        {
            // 解析运营商地址 (支持域名, DNS 解析)
            var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
                ? trunk.Registrar : $"sip:{trunk.Registrar}");
            var registrarEP = SipUriUtility.ResolveSipUriEndPoint(registrarUri, _options.DnsServer, _logger);

            var (fromUser, fromDomain) = ResolveFromParts(trunk);
            var clientUri = ResolveClientUri(trunk, registrarUri);

            // 使用 NetworkUtility 获取本机 IP (消除重复)
            var (outboundIp, outboundPort) = ResolveOutboundAddress(trunk);
            var localIP = NetworkUtility.GetLocalIPv4();
            var mainChannelPort = _mainTransport?.GetSIPChannels().FirstOrDefault()?.ListeningSIPEndPoint.Port ?? _options.SipPort;

            // 构建 REGISTER 请求
            var registerRequestUri = SIPURI.ParseSIPURI($"sip:{clientUri.HostAddress}");
            var registerRequest = SIPRequest.GetRequest(SIPMethodsEnum.REGISTER, registerRequestUri);

            // Route 头
            var routeUri = SIPURI.ParseSIPURI($"sip:{registrarUri.HostAddress}");
            registerRequest.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

            // Display name
            var displayName = $"{fromUser}@{clientUri.HostAddress}";

            // From/To
            registerRequest.Header.From = new SIPFromHeader(displayName,
                new SIPURI(fromUser, fromDomain, null, SIPSchemesEnum.sip),
                state.FromTag);
            registerRequest.Header.To = new SIPToHeader(displayName, clientUri, null);
            registerRequest.Header.CallId = state.CallId;
            registerRequest.Header.CSeq = state.CSeq;
            registerRequest.Header.Expires = trunk.RegisterExpiry;

            // Contact
            var contactUser = !string.IsNullOrEmpty(trunk.ContactUser) ? trunk.ContactUser : fromUser;
            var contactHost = $"{localIP}:{mainChannelPort}";
            var contactUri = new SIPURI(contactUser, contactHost, null, SIPSchemesEnum.sip);
            contactUri.Parameters.Set("ob", null);
            registerRequest.Header.Contact = [new SIPContactHeader(displayName, contactUri)];

            // 修正 Via 头 (使用 NetworkUtility)
            NetworkUtility.FixViaHeader(registerRequest, localIP, mainChannelPort, _logger);

            // 如果有缓存的 nonce, 携带 Authorization 头避免 401 往返
            if (!string.IsNullOrEmpty(state.Nonce))
            {
                AddAuthorizationHeader(registerRequest, trunk, state);
            }

            _logger.LogInformation("向运营商 {Registrar} 发送 REGISTER (Trunk={Name}, 尝试 #{Attempt}, CSeq={CSeq}, " +
                "From={From}, To={To}, Contact={Contact}, OutboundIP={OutboundIP}, CallId={CallId})",
                trunk.Registrar, trunk.Name, state.RegisterAttempts, state.CSeq,
                registerRequest.Header.From.FromURI, registerRequest.Header.To.ToURI,
                contactUri, $"{localIP}:{mainChannelPort}", state.CallId);

            _logger.LogInformation("REGISTER 报文:\n{Packet}", registerRequest.ToString());

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
                _logger.LogInformation("Trunk {Name} 收到 401 挑战, 重新认证 (CallId={CallId})", trunk.Name, state.CallId);
                await HandleTrunkAuthChallenge(trunk, response, remoteEP);
                break;

            case SIPResponseStatusCodesEnum.Forbidden:
                _logger.LogError("Trunk {Name} 注册被拒绝 (403 Forbidden): {Reason}",
                    trunk.Name, response.ReasonPhrase);
                _logger.LogInformation("403 响应报文:\n{Packet}", response.ToString());
                break;

            case SIPResponseStatusCodesEnum.NotFound:
                _logger.LogWarning("Trunk {Name} 注册响应: 404 NotFound (可能是回环或账号不存在)", trunk.Name);
                break;

            case SIPResponseStatusCodesEnum.ServiceUnavailable:
                _logger.LogWarning("Trunk {Name} 注册响应: 503 Service Unavailable (CallId={CallId}, " +
                    "可能原因: Contact/Via地址运营商无法路由, 认证格式错误, 或运营商服务器暂时不可用)",
                    trunk.Name, state.CallId);
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
    /// 使用 DigestUtility 统一计算 MD5 (消除与 DigestAuthenticator 的重复)
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

        // CSeq 递增
        state.CSeq++;

        // 使用 NetworkUtility 获取本机 IP (消除重复)
        var (outboundIp, outboundPort) = ResolveOutboundAddress(trunk);
        var localIP = NetworkUtility.GetLocalIPv4();
        var mainChannelPort = _mainTransport?.GetSIPChannels().FirstOrDefault()?.ListeningSIPEndPoint.Port ?? _options.SipPort;

        // 构建 REGISTER 请求 (带认证)
        var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
            ? trunk.Registrar : $"sip:{trunk.Registrar}");

        var (fromUser, fromDomain) = ResolveFromParts(trunk);
        var clientUri = ResolveClientUri(trunk, registrarUri);
        var contactUser = !string.IsNullOrEmpty(trunk.ContactUser) ? trunk.ContactUser : fromUser;

        var registerRequestUri = SIPURI.ParseSIPURI($"sip:{clientUri.HostAddress}");
        var registerRequest = SIPRequest.GetRequest(SIPMethodsEnum.REGISTER, registerRequestUri);

        // Route 头
        var routeUri = SIPURI.ParseSIPURI($"sip:{registrarUri.HostAddress}");
        registerRequest.Header.Routes.PushRoute(new SIPRoute(routeUri, true));

        // Display name
        var displayName = $"{fromUser}@{clientUri.HostAddress}";

        // From/To (使用缓存的 FromTag)
        registerRequest.Header.From = new SIPFromHeader(displayName,
            new SIPURI(fromUser, fromDomain, null, SIPSchemesEnum.sip),
            state.FromTag);
        registerRequest.Header.To = new SIPToHeader(displayName, clientUri, null);
        registerRequest.Header.CallId = state.CallId;
        registerRequest.Header.CSeq = state.CSeq;
        registerRequest.Header.Expires = trunk.RegisterExpiry;

        // Contact
        var contactHost = $"{localIP}:{mainChannelPort}";
        var contactUri = new SIPURI(contactUser, contactHost, null, SIPSchemesEnum.sip);
        contactUri.Parameters.Set("ob", null);
        registerRequest.Header.Contact = [new SIPContactHeader(displayName, contactUri)];

        // 修正 Via 头 (使用 NetworkUtility)
        NetworkUtility.FixViaHeader(registerRequest, localIP, mainChannelPort, _logger);

        // === Digest 认证 (使用 DigestUtility 统一计算) ===
        var authUri = $"sip:{clientUri.HostAddress}";
        var computedDigest = DigestUtility.BuildManualDigest(
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

        _logger.LogInformation("带认证 REGISTER 报文:\n{Packet}", registerRequest.ToString());

        if (_mainTransport != null)
            await _mainTransport.SendRequestAsync(registrarEP, registerRequest);
    }

    /// <summary>
    /// 为 REGISTER 请求添加 Authorization 头 (用于带缓存的 nonce 刷新注册)
    /// </summary>
    private void AddAuthorizationHeader(SIPRequest request, SipTrunkConfig trunk, TrunkRegistrationState state)
    {
        if (string.IsNullOrEmpty(state.Nonce))
            return;

        var clientUriForAuth = ResolveClientUri(trunk, SIPURI.ParseSIPURI(
            trunk.Registrar.StartsWith("sip:") ? trunk.Registrar : $"sip:{trunk.Registrar}"));
        var authUri = $"sip:{clientUriForAuth.HostAddress}";
        var realm = !string.IsNullOrEmpty(trunk.Realm) ? trunk.Realm
            : !string.IsNullOrEmpty(state.Opaque) ? $"{clientUriForAuth.HostAddress}"
            : trunk.Registrar;
        var computedDigest = DigestUtility.BuildManualDigest(
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
    /// 手动构建完整的 SIPAuthorisationDigest (公开接口, 供外呼 INVITE 使用)
    /// 委托给 DigestUtility 统一实现
    /// </summary>
    public SIPAuthorisationDigest BuildManualDigest(
        string username, string password, string realm,
        string nonce, string qop, string uri, string method,
        string opaque)
    {
        return DigestUtility.BuildManualDigest(username, password, realm, nonce, qop, uri, method, opaque);
    }

    /// <summary>
    /// 定时刷新所有 Trunk 注册
    /// </summary>
    private async Task RefreshAllRegistrations()
    {
        foreach (var trunk in _options.Trunks.Where(t => t.Enabled))
        {
            var state = _trunkStates[trunk.Name];
            if (state.LastRegisteredAt == null)
            {
                await RegisterTrunk(trunk);
                continue;
            }

            var age = DateTime.UtcNow - state.LastRegisteredAt.Value;
            var remaining = state.RegisterExpiry - (int)age.TotalSeconds;

            if (remaining < _runtime.TrunkRefreshThresholdSeconds)
            {
                _logger.LogInformation("Trunk {Name} 注册即将过期 (剩余 {Remaining}s), 刷新注册",
                    trunk.Name, remaining);
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
    }

    /// <summary>
    /// 解析 From 头的 user 和 domain
    /// </summary>
    private (string user, string domain) ResolveFromParts(SipTrunkConfig trunk)
    {
        var registrarUri = SIPURI.ParseSIPURI(trunk.Registrar.StartsWith("sip:")
            ? trunk.Registrar : $"sip:{trunk.Registrar}");

        var fromUser = trunk.FromUser;
        if (string.IsNullOrEmpty(fromUser))
        {
            var atIdx = trunk.Username.IndexOf('@');
            fromUser = atIdx > 0 ? trunk.Username[..atIdx] : trunk.Username;
        }

        var fromDomain = !string.IsNullOrEmpty(trunk.FromDomain)
            ? trunk.FromDomain
            : registrarUri.HostAddress;

        return (fromUser, fromDomain);
    }

    /// <summary>
    /// 解析 To 头的 Client URI (注册身份 AoR)
    /// </summary>
    private SIPURI ResolveClientUri(SipTrunkConfig trunk, SIPURI registrarUri)
    {
        if (!string.IsNullOrEmpty(trunk.ClientUri))
        {
            return SIPURI.ParseSIPURI(trunk.ClientUri.StartsWith("sip:")
                ? trunk.ClientUri : $"sip:{trunk.ClientUri}");
        }

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
