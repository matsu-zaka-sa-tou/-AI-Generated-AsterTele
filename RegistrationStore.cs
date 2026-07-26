using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// 已注册分机的信息
/// </summary>
public class RegisteredExtension
{
    /// <summary>分机号</summary>
    public string Number { get; set; } = string.Empty;

    /// <summary>密码</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>显示名</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>注册的 Contact URI (来自 REGISTER 的 Contact 头)</summary>
    public SIPURI ContactURI { get; set; } = SIPURI.ParseSIPURI("sip:0.0.0.0");

    /// <summary>客户端的源地址</summary>
    public SIPEndPoint SourceEndPoint { get; set; } = SIPEndPoint.Empty;

    /// <summary>注册时间</summary>
    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;

    /// <summary>过期时间 (秒)</summary>
    public long Expires { get; set; } = 3600;

    /// <summary>Call-ID (用于匹配后续 REGISTER 刷新)</summary>
    public string CallId { get; set; } = string.Empty;

    /// <summary>是否已过期</summary>
    public bool IsExpired => DateTime.UtcNow > RegisteredAt + TimeSpan.FromSeconds(Expires);

    public override string ToString() => $"{Number} @ {ContactURI} (expires={Expires})";
}

/// <summary>
/// 分机注册存储
/// 管理所有已注册分机的 Contact 信息
/// </summary>
public class RegistrationStore
{
    private readonly ConcurrentDictionary<string, RegisteredExtension> _registrations = new();
    private readonly Dictionary<string, ExtensionConfig> _extensionConfigs = new();
    private readonly SipOptions _options;
    private readonly ILogger<RegistrationStore> _logger;

    public RegistrationStore(IOptions<SipOptions> options, ILogger<RegistrationStore> logger)
    {
        _options = options.Value;
        _logger = logger;

        // 加载分机配置
        foreach (var ext in _options.Extensions)
        {
            _extensionConfigs[ext.Number] = ext;
            _logger.LogInformation("加载分机配置: {Number} / {DisplayName}", ext.Number, ext.DisplayName);
        }
    }

    /// <summary>
    /// 获取分机配置密码 (用于 Digest 认证)
    /// </summary>
    public ExtensionConfig? GetExtensionConfig(string number)
    {
        return _extensionConfigs.TryGetValue(number, out var config) ? config : null;
    }

    /// <summary>
    /// 判断分机号是否存在于配置中
    /// </summary>
    public bool ExtensionExists(string number) => _extensionConfigs.ContainsKey(number);

    /// <summary>
    /// 注册或刷新分机
    /// </summary>
    public void Register(RegisteredExtension registration)
    {
        _registrations[registration.Number] = registration;
        _logger.LogInformation("分机 {Number} 已注册: Contact={Contact}, Source={Source}, Expires={Expires}",
            registration.Number, registration.ContactURI, registration.SourceEndPoint, registration.Expires);
    }

    /// <summary>
    /// 注销分机
    /// </summary>
    public void Unregister(string number)
    {
        if (_registrations.TryRemove(number, out var reg))
        {
            _logger.LogInformation("分机 {Number} 已注销", number);
        }
    }

    /// <summary>
    /// 查找已注册的分机信息
    /// </summary>
    public RegisteredExtension? GetRegistration(string number)
    {
        if (_registrations.TryGetValue(number, out var reg))
        {
            if (reg.IsExpired)
            {
                _registrations.TryRemove(number, out _);
                _logger.LogWarning("分机 {Number} 注册已过期", number);
                return null;
            }
            return reg;
        }
        return null;
    }

    /// <summary>
    /// 获取所有已注册的分机
    /// </summary>
    public IEnumerable<RegisteredExtension> GetAllRegistrations()
    {
        return _registrations.Values.Where(r => !r.IsExpired).ToList();
    }

    /// <summary>
    /// 清理过期注册
    /// </summary>
    public void CleanupExpired()
    {
        foreach (var kv in _registrations)
        {
            if (kv.Value.IsExpired)
            {
                _registrations.TryRemove(kv.Key, out _);
                _logger.LogInformation("清理过期注册: {Number}", kv.Key);
            }
        }
    }
}
