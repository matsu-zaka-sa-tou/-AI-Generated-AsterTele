using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// SIP Digest 认证器
/// 处理 REGISTER/INVITE 的 Digest 挑战-响应流程
/// </summary>
public class DigestAuthenticator
{
    private readonly string _realm;
    private readonly Dictionary<string, DateTime> _pendingNonces = new();
    private readonly object _nonceLock = new();
    private static readonly TimeSpan NonceExpiry = TimeSpan.FromMinutes(5);
    private readonly ILogger? _logger;

    public DigestAuthenticator(string realm, ILogger<DigestAuthenticator>? logger = null)
    {
        _realm = realm;
        _logger = logger;
    }

    /// <summary>
    /// 生成 401 Unauthorized 响应，附带 Digest 挑战
    /// </summary>
    public SIPResponse Challenge(SIPRequest request)
    {
        var nonce = GenerateNonce();

        lock (_nonceLock)
        {
            CleanupExpiredNonces();
            _pendingNonces[nonce] = DateTime.UtcNow;
        }

        var response = SIPResponse.GetResponse(request, SIPResponseStatusCodesEnum.Unauthorised, "Unauthorized");

        // 构造 WWW-Authenticate 头
        var digest = new SIPAuthorisationDigest(SIPAuthorisationHeadersEnum.WWWAuthenticate, DigestAlgorithmsEnum.MD5);
        digest.Realm = _realm;
        digest.Nonce = nonce;
        digest.Qop = "auth";
        digest.DigestAlgorithm = DigestAlgorithmsEnum.MD5;
        digest.Opaque = string.Empty;

        var authHeader = new SIPAuthenticationHeader(digest);
        response.Header.AuthenticationHeaders.Add(authHeader);

        return response;
    }

    /// <summary>
    /// 验证 Digest 认证响应
    /// 使用 DigestUtility 统一的 MD5 计算
    /// </summary>
    public bool Validate(SIPRequest request, string username, string password)
    {
        var authHeaders = request.Header.AuthenticationHeaders;
        if (authHeaders == null || authHeaders.Count == 0)
            return false;

        var authHeader = authHeaders[0];
        var digest = authHeader.SIPDigest;
        if (digest == null)
            return false;

        if (string.IsNullOrEmpty(digest.Nonce) || string.IsNullOrEmpty(digest.Response))
            return false;

        // 验证 nonce 有效性 (时间窗口内允许复用)
        lock (_nonceLock)
        {
            CleanupExpiredNonces();
            if (!_pendingNonces.ContainsKey(digest.Nonce))
            {
                _logger?.LogWarning("Nonce 无效或已过期: {Nonce} (活跃 nonces: {Count})",
                    digest.Nonce[..Math.Min(8, digest.Nonce.Length)], _pendingNonces.Count);
                return false;
            }
        }

        // 使用 DigestUtility 手动计算验证 (绕过 SIPSorcery SetCredentials bug)
        var expectedDigest = DigestUtility.BuildManualDigest(
            username, password,
            _realm,
            digest.Nonce,
            digest.Qop ?? "",
            digest.URI ?? request.URI.ToString(),
            request.Method.ToString(),
            digest.Opaque ?? "");

        // 如果有 Cnonce, 用完整公式重新计算
        if (!string.IsNullOrEmpty(digest.Cnonce) && !string.IsNullOrEmpty(digest.Qop))
        {
            var ha1 = DigestUtility.ComputeMD5($"{username}:{_realm}:{password}");
            var ha2 = DigestUtility.ComputeMD5($"{request.Method}:{digest.URI ?? request.URI.ToString()}");
            var ncStr = (digest.NonceCount > 0 ? digest.NonceCount : 1).ToString("D8");
            var expectedResponse = DigestUtility.ComputeMD5(
                $"{ha1}:{digest.Nonce}:{ncStr}:{digest.Cnonce}:{digest.Qop}:{ha2}");

            var isValid = string.Equals(expectedResponse, digest.Response, StringComparison.OrdinalIgnoreCase);

            if (!isValid)
            {
                _logger?.LogWarning("Digest 验证失败: 期望={Expected}, 收到={Actual}, Realm={Realm}, URI={URI}, " +
                    "Username={Username}, Qop={Qop}, Cnonce={Cnonce}, NC={NC}",
                    expectedResponse?[..Math.Min(8, expectedResponse.Length)],
                    digest.Response?[..Math.Min(8, digest.Response.Length)],
                    _realm, digest.URI, username, digest.Qop, digest.Cnonce, digest.NonceCount);
            }

            return isValid;
        }

        // Fallback: 无 qop 场景
        var isValidSimple = string.Equals(expectedDigest.Response, digest.Response, StringComparison.OrdinalIgnoreCase);
        if (!isValidSimple)
        {
            _logger?.LogWarning("Digest 验证失败 (无qop): 期望={Expected}, 收到={Actual}",
                expectedDigest.Response?[..Math.Min(8, expectedDigest.Response.Length)],
                digest.Response?[..Math.Min(8, digest.Response.Length)]);
        }

        return isValidSimple;
    }

    /// <summary>
    /// 清理过期的 nonce
    /// </summary>
    private void CleanupExpiredNonces()
    {
        var cutoff = DateTime.UtcNow - NonceExpiry;
        var expired = _pendingNonces.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
        foreach (var nonce in expired)
            _pendingNonces.Remove(nonce);
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
