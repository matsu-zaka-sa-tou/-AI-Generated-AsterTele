namespace AsterTele;

/// <summary>
/// 语音信箱会话
/// 当呼叫转移目标为 "voicemail" 时, 理论上应:
/// 1. 应答呼叫 (200 OK + SDP)
/// 2. 播放语音信箱提示音 ("请在滴声后留言")
/// 3. 录音 (RTP 音频 → 文件)
/// 4. 保存留言记录
/// 
/// 当前骨架: 仅记录日志, 不执行 RTP 操作
/// </summary>
public class VoiceMailSession
{
    public string SessionId { get; } = Guid.NewGuid().ToString("N")[..8];

    /// <summary>被叫分机号 (信箱所属)</summary>
    public string MailboxExtension { get; set; } = string.Empty;

    /// <summary>主叫号码 (留言者)</summary>
    public string? CallerNumber { get; set; }

    /// <summary>信箱状态</summary>
    public VoiceMailState State { get; set; } = VoiceMailState.WaitingForAnswer;

    /// <summary>创建时间</summary>
    public DateTime CreatedAt { get; } = DateTime.UtcNow;

    /// <summary>留言文件路径 (预留)</summary>
    public string? RecordingPath { get; set; }

    /// <summary>留言时长 (秒, 预留)</summary>
    public int RecordingDurationSeconds { get; set; }

    public override string ToString() => $"[VM-{SessionId}] Mailbox={MailboxExtension} Caller={CallerNumber} State={State}";
}

public enum VoiceMailState
{
    /// <summary>等待应答</summary>
    WaitingForAnswer,

    /// <summary>播放提示音</summary>
    PlayingGreeting,

    /// <summary>录音中</summary>
    Recording,

    /// <summary>已完成</summary>
    Completed,

    /// <summary>失败</summary>
    Failed
}
