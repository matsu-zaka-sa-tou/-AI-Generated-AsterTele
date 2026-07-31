namespace AsterTele;

/// <summary>
/// RTP 桥接接口
/// 连接 SIP 信令层与 RTP 媒体流
/// 实现 IVR 语音播放、语音信箱录音、媒体转码等需要 RTP 的功能
///
/// 使用方式:
/// 1. 在 DI 中注册 IRtpBridge 实现 (如 NullRtpBridge 或 NaudioRtpBridge)
/// 2. InviteHandler/ByeHandler 在需要媒体操作时调用 IRtpBridge
/// 3. SIP 信令层 (200 OK / BYE) 与 RTP 层 (音频流) 通过此接口解耦
///
/// SDP 媒体锚定:
/// - RewriteSdpToCallee: 在构造发给被叫的 INVITE 时, 将 SDP 的 RTP 地址/端口改为 AsterTele 的
/// - RewriteSdpToCaller: 在转发 200 OK/183 给主叫时, 将 SDP 的 RTP 地址/端口改为 AsterTele 的
///   使得 RTP 流经过 AsterTele, 实现媒体锚定
///
/// 扩展示例:
/// - NaudioRtpBridge: 使用 NAudio 进行音频编解码 (当前实现)
/// - RtpFfmpegBridge: 使用 ffmpeg 进行音频编解码
/// </summary>
public interface IRtpBridge
{
    /// <summary>
    /// 重写发往被叫侧的 SDP (在构造 INVITE 给被叫时调用)
    /// 将原始 SDP 中的 RTP 地址/端口替换为 AsterTele 的被叫侧端口
    /// 同时从原始 SDP 中提取主叫方的 RTP 端点, 存储用于后续转发
    /// </summary>
    /// <param name="session">呼叫会话</param>
    /// <param name="callerSdp">主叫方原始 SDP (来自主叫 INVITE)</param>
    /// <param name="calleeSideIp">被叫侧看到的 AsterTele IP (如 OutboundAddress)</param>
    /// <returns>重写后的 SDP; null 表示不支持媒体锚定, 使用原始 SDP</returns>
    string? RewriteSdpToCallee(CallSession session, string callerSdp, string calleeSideIp);

    /// <summary>
    /// 重写发往主叫侧的 SDP (在转发 200 OK/183 给主叫时调用)
    /// 将原始 SDP 中的 RTP 地址/端口替换为 AsterTele 的主叫侧端口
    /// 同时从原始 SDP 中提取被叫方的 RTP 端点, 存储用于后续转发
    /// </summary>
    /// <param name="session">呼叫会话</param>
    /// <param name="calleeSdp">被叫方原始 SDP (来自被叫 200 OK/183)</param>
    /// <param name="callerSideIp">主叫侧看到的 AsterTele IP (如 AdvertisedAddress)</param>
    /// <returns>重写后的 SDP; null 表示不支持媒体锚定, 使用原始 SDP</returns>
    string? RewriteSdpToCaller(CallSession session, string calleeSdp, string callerSideIp);

    /// <summary>SIP 会话建立通知 (200 OK 后触发, 启动 RTP 双向转发)</summary>
    /// <param name="session">呼叫会话</param>
    /// <param name="sdpAnswer">被叫侧 SDP 应答</param>
    Task OnSessionEstablished(CallSession session, string sdpAnswer);

    /// <summary>SIP 会话终止通知 (BYE 后触发, 停止转发并释放端口)</summary>
    /// <param name="session">呼叫会话</param>
    Task OnSessionTerminated(CallSession session);

    /// <summary>播放提示音 (如 IVR 欢迎语、语音信箱提示)</summary>
    /// <param name="session">呼叫会话</param>
    /// <param name="promptId">提示音标识 (如 "welcome", "voicemail_greeting")</param>
    /// <param name="ct">取消令牌 (BYE/CANCEL 时取消播放)</param>
    Task PlayPromptAsync(CallSession session, string promptId, CancellationToken ct);

    /// <summary>停止播放</summary>
    Task StopPromptAsync(CallSession session);

    /// <summary>开始录音 (语音信箱)</summary>
    /// <param name="session">呼叫会话</param>
    /// <param name="outputPath">录音输出路径</param>
    /// <param name="maxDurationSeconds">最大录音时长 (秒)</param>
    /// <param name="ct">取消令牌</param>
    Task StartRecordingAsync(CallSession session, string outputPath, int maxDurationSeconds, CancellationToken ct);

    /// <summary>停止录音</summary>
    /// <returns>录音文件路径, null 表示录音失败</returns>
    Task<string?> StopRecordingAsync(CallSession session);

    /// <summary>获取媒体能力 SDP (用于应答媒体会话)</summary>
    /// <returns>SDP 字符串, null 表示无媒体能力</returns>
    string? GetMediaSdp(CallSession session);

    /// <summary>修改媒体会话 (re-INVITE)</summary>
    /// <param name="session">呼叫会话</param>
    /// <param name="newSdp">新的 SDP 提议</param>
    /// <returns>修改后的 SDP 应答, null 表示修改失败</returns>
    Task<string?> ModifySessionAsync(CallSession session, string newSdp);

    /// <summary>检测是否支持媒体操作 (IVR/语音信箱/录音)</summary>
    bool IsMediaAvailable { get; }
}

/// <summary>
/// RTP 桥接空实现
/// 当 RTP 功能未就绪时使用, 所有媒体操作静默跳过
/// SDP 重写返回 null, 信令层将使用原始 SDP (纯透传模式)
/// </summary>
public class NullRtpBridge : IRtpBridge
{
    public bool IsMediaAvailable => false;

    public string? RewriteSdpToCallee(CallSession session, string callerSdp, string calleeSideIp) => null;
    public string? RewriteSdpToCaller(CallSession session, string calleeSdp, string callerSideIp) => null;
    public Task OnSessionEstablished(CallSession session, string sdpAnswer) => Task.CompletedTask;
    public Task OnSessionTerminated(CallSession session) => Task.CompletedTask;
    public Task PlayPromptAsync(CallSession session, string promptId, CancellationToken ct) => Task.CompletedTask;
    public Task StopPromptAsync(CallSession session) => Task.CompletedTask;
    public Task StartRecordingAsync(CallSession session, string outputPath, int maxDurationSeconds, CancellationToken ct) => Task.CompletedTask;
    public Task<string?> StopRecordingAsync(CallSession session) => Task.FromResult<string?>(null);
    public string? GetMediaSdp(CallSession session) => null;
    public Task<string?> ModifySessionAsync(CallSession session, string newSdp) => Task.FromResult<string?>(null);
}
