using System.Security.Cryptography;
using System.Text;
using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// Digest 认证工具类
/// 统一 MD5 计算和 Digest 构建逻辑, 消除 SipTrunkManager 和 DigestAuthenticator 中的重复实现
/// SIPSorcery 10.0.12 存在 SetCredentials 不计算 Response 的 bug, 此类提供可靠的手动计算
/// </summary>
public static class DigestUtility
{
    /// <summary>
    /// 计算 MD5 哈希的十六进制字符串
    /// </summary>
    public static string ComputeMD5(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// 生成随机 Cnonce (16 位十六进制)
    /// </summary>
    public static string GenerateCnonce()
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
    }

    /// <summary>
    /// 手动构建完整的 SIPAuthorisationDigest (绕过 SIPSorcery 10.0.12 SetCredentials bug)
    /// SetCredentials() 在 qop=auth 时不计算 Response/Cnonce/NonceCount
    /// 此方法手动计算 MD5 Digest 并设置所有字段
    /// </summary>
    public static SIPAuthorisationDigest BuildManualDigest(
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
}
