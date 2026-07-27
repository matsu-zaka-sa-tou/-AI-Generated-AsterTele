using SIPSorcery.SIP;

namespace AsterTele;

/// <summary>
/// IVR 会话
/// 跟踪入站 IVR 交互状态 (提示音播放 → DTMF 收集 → 路由到分机)
/// </summary>
public class IvrSession
{
    public string SessionId { get; } = Guid.NewGuid().ToString("N")[..8];

    /// <summary>入站 DID 号码</summary>
    public string DidNumber { get; set; } = string.Empty;

    /// <summary>IVR 拨号前缀 (如 "8")</summary>
    public string IvrPrefix { get; set; } = "8";

    /// <summary>已收集的 DTMF 数字</summary>
    public string CollectedDigits { get; set; } = string.Empty;

    /// <summary>主叫号码</summary>
    public string? CallerNumber { get; set; }

    /// <summary>主叫端点</summary>
    public SIPEndPoint CallerEP { get; set; } = SIPEndPoint.Empty;

    /// <summary>原始 INVITE 请求</summary>
    public SIPRequest? OriginalInvite { get; set; }

    /// <summary>创建时间</summary>
    public DateTime CreatedAt { get; } = DateTime.UtcNow;

    /// <summary>IVR 状态</summary>
    public IvrState State { get; set; } = IvrState.WaitingForAnswer;

    /// <summary>DTMF 收集超时取消令牌</summary>
    public CancellationTokenSource? DtmfCts { get; set; }

    /// <summary>最大 DTMF 位数 (分机号长度)</summary>
    public int MaxDigits { get; set; } = 4;

    /// <summary>DTMF 收集超时 (秒)</summary>
    public int DtmfTimeout { get; set; } = 10;

    public override string ToString() => $"[IVR-{SessionId}] DID={DidNumber} Digits={CollectedDigits} State={State}";
}

public enum IvrState
{
    /// <summary>等待应答 (SDP 协商)</summary>
    WaitingForAnswer,

    /// <summary>播放提示音 (RTP 音频)</summary>
    PlayingPrompt,

    /// <summary>收集 DTMF 拨号</summary>
    CollectingDigits,

    /// <summary>路由到目标分机</summary>
    Routing,

    /// <summary>已完成</summary>
    Completed,

    /// <summary>失败</summary>
    Failed
}
