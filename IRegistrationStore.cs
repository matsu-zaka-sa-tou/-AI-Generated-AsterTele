using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// 分机注册存储接口
/// 管理所有已注册分机的 Contact 信息
/// </summary>
public interface IRegistrationStore
{
    ExtensionConfig? GetExtensionConfig(string number);
    bool ExtensionExists(string number);
    void Register(RegisteredExtension registration);
    void Unregister(string number);
    RegisteredExtension? GetRegistration(string number);
    IEnumerable<RegisteredExtension> GetAllRegistrations();
    void CleanupExpired();
}
