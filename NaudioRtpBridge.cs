using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NAudio.Codecs;
using NAudio.Wave;

namespace AsterTele;

/// <summary>
/// 基于 NAudio 的 RTP 桥接实现
/// 
/// 架构: AsterTele 作为媒体锚点, 每个通话分配两个 UDP 端口:
///   - CallerPort: 主叫侧发RTP到这个端口, AsterTele 从这个端口转发到被叫
///   - CalleePort: 被叫侧发RTP到这个端口, AsterTele 从这个端口转发到主叫
/// 
/// RTP 包流程:
///   主叫 ──RTP──> AsterTele:CallerPort ──转发──> 被叫RTP端点
///   被叫 ──RTP──> AsterTele:CalleePort ──转发──> 主叫RTP端点
/// 
/// NAudio 负责:
///   - G.711 A-Law (PCMA, pt=8) / μ-Law (PCMU, pt=0) 解码 → 录音为 WAV
///   - WAV 文件读取 → G.711 编码 → RTP 注入 (播放提示音)
/// </summary>
public class NaudioRtpBridge : IRtpBridge
{
    private readonly ILogger<NaudioRtpBridge> _logger;
    private readonly RtpPortAllocator _portAllocator;
    private readonly ConcurrentDictionary<string, RtpRelay> _relays = new();

    public bool IsMediaAvailable => true;

    public NaudioRtpBridge(ILogger<NaudioRtpBridge> logger, RtpPortAllocator portAllocator)
    {
        _logger = logger;
        _portAllocator = portAllocator;
    }

    // ===== SDP 媒体锚定 =====

    public string? RewriteSdpToCallee(CallSession session, string callerSdp, string calleeSideIp)
    {
        var relay = GetOrCreateRelay(session);

        // 从主叫方原始 SDP 提取主叫的 RTP 端点
        var (callerIp, callerPort) = SdpUtility.ParseRtpEndpoint(callerSdp);
        if (callerIp != null && callerPort != null)
        {
            relay.SetCallerRemoteEP(new IPEndPoint(IPAddress.Parse(callerIp), callerPort.Value));
            _logger.LogDebug("RTP 主叫端点: {Ip}:{Port} (会话 {SessionId})", callerIp, callerPort, session.SessionId);
        }

        // 重写 SDP: IP → 被叫侧看到的 AsterTele 地址, 端口 → AsterTele 的被叫侧端口
        var sdp = SdpUtility.ReplaceSdpIpAddress(callerSdp, calleeSideIp);
        sdp = SdpUtility.ReplaceSdpMediaPort(sdp, relay.CalleeLocalPort);

        _logger.LogInformation("RTP SDP 锚定 → 被叫侧: {Ip}:{Port} (会话 {SessionId})",
            calleeSideIp, relay.CalleeLocalPort, session.SessionId);

        // 外呼 INVITE 发出后立即启动 RTP 监听
        // 不等 200 OK: 运营商可能在 183 早期媒体中发 RTP, 也可能先 200 OK 再发忙音 RTP
        // 提前监听端口, 运营商发来的 RTP 包一到就能学习到真实地址
        if (!relay.IsRunning)
        {
            relay.StartRelay();
            _logger.LogInformation("RTP 双向转发已启动 (INVITE 发出后, 会话 {SessionId})", session.SessionId);
        }

        return sdp;
    }

    public string? RewriteSdpToCaller(CallSession session, string calleeSdp, string callerSideIp)
    {
        var relay = GetOrCreateRelay(session);

        // 从被叫方原始 SDP 提取被叫的 RTP 端点
        var (calleeIp, calleePort) = SdpUtility.ParseRtpEndpoint(calleeSdp);
        if (calleeIp != null && calleePort != null)
        {
            relay.SetCalleeRemoteEP(new IPEndPoint(IPAddress.Parse(calleeIp), calleePort.Value));
            _logger.LogDebug("RTP 被叫端点: {Ip}:{Port} (会话 {SessionId})", calleeIp, calleePort, session.SessionId);
        }

        // 重写 SDP: IP → 主叫侧看到的 AsterTele 地址, 端口 → AsterTele 的主叫侧端口
        var sdp = SdpUtility.ReplaceSdpIpAddress(calleeSdp, callerSideIp);
        sdp = SdpUtility.ReplaceSdpMediaPort(sdp, relay.CallerLocalPort);

        _logger.LogInformation("RTP SDP 锚定 → 主叫侧: {Ip}:{Port} (会话 {SessionId})",
            callerSideIp, relay.CallerLocalPort, session.SessionId);

        // 183/200 OK 带被叫 SDP 时更新端点, RTP 转发已在 INVITE 时启动
        // 如果未启动 (如入站方向首次调用), 立即启动
        if (!relay.IsRunning)
        {
            relay.StartRelay();
            _logger.LogInformation("RTP 双向转发已启动 (被叫 SDP 到达, 会话 {SessionId})", session.SessionId);
        }

        return sdp;
    }

    // ===== 会话生命周期 =====

    public Task OnSessionEstablished(CallSession session, string sdpAnswer)
    {
        var relay = GetOrCreateRelay(session);

        // 从 200 OK SDP 更新被叫端点
        var (calleeIp, calleePort) = SdpUtility.ParseRtpEndpoint(sdpAnswer);
        if (calleeIp != null && calleePort != null)
        {
            relay.SetCalleeRemoteEP(new IPEndPoint(IPAddress.Parse(calleeIp), calleePort.Value));
        }

        // 200 OK 可能携带更新的被叫端点, 但 RTP 转发已在 INVITE 时启动
        // 地址学习会从实际 RTP 包修正不可路由的 SDP IP
        if (!relay.IsRunning)
        {
            relay.StartRelay();
            _logger.LogInformation("RTP 双向转发已启动 (200 OK 后, 会话 {SessionId})", session.SessionId);
        }

        return Task.CompletedTask;
    }

    public Task OnSessionTerminated(CallSession session)
    {
        if (_relays.TryRemove(session.SessionId, out var relay))
        {
            relay.Dispose();
            _logger.LogInformation("RTP 桥接已释放 (会话 {SessionId})", session.SessionId);
        }
        return Task.CompletedTask;
    }

    // ===== NAudio 音频功能 =====

    public Task PlayPromptAsync(CallSession session, string promptId, CancellationToken ct)
    {
        if (!_relays.TryGetValue(session.SessionId, out var relay))
        {
            _logger.LogWarning("播放提示音失败: 未找到会话 {SessionId} 的 RTP 桥接", session.SessionId);
            return Task.CompletedTask;
        }

        relay.PlayPrompt(promptId, ct);
        return Task.CompletedTask;
    }

    public Task StopPromptAsync(CallSession session)
    {
        if (_relays.TryGetValue(session.SessionId, out var relay))
            relay.StopPrompt();
        return Task.CompletedTask;
    }

    public Task StartRecordingAsync(CallSession session, string outputPath, int maxDurationSeconds, CancellationToken ct)
    {
        if (!_relays.TryGetValue(session.SessionId, out var relay))
        {
            _logger.LogWarning("录音失败: 未找到会话 {SessionId} 的 RTP 桥接", session.SessionId);
            return Task.CompletedTask;
        }

        relay.StartRecording(outputPath);
        _logger.LogInformation("RTP 录音开始: {Path} (会话 {SessionId}, 最长 {MaxS}s)",
            outputPath, session.SessionId, maxDurationSeconds);
        return Task.CompletedTask;
    }

    public Task<string?> StopRecordingAsync(CallSession session)
    {
        if (_relays.TryGetValue(session.SessionId, out var relay))
        {
            var path = relay.StopRecording();
            if (path != null)
                _logger.LogInformation("RTP 录音结束: {Path} (会话 {SessionId})", path, session.SessionId);
            return Task.FromResult(path);
        }
        return Task.FromResult<string?>(null);
    }

    public string? GetMediaSdp(CallSession session) => null; // TODO: 生成 AsterTele 的 SDP offer

    public Task<string?> ModifySessionAsync(CallSession session, string newSdp) => Task.FromResult<string?>(null);

    // ===== 内部方法 =====

    private RtpRelay GetOrCreateRelay(CallSession session)
    {
        return _relays.GetOrAdd(session.SessionId, _ =>
        {
            var relay = new RtpRelay(_portAllocator, _logger);
            _logger.LogInformation("RTP 桥接创建: CallerPort={CP}, CalleePort={CltP} (会话 {SessionId})",
                relay.CallerLocalPort, relay.CalleeLocalPort, session.SessionId);
            return relay;
        });
    }
}

/// <summary>
/// 单个通话的 RTP 双向转发器
/// 
/// 两个 UdpClient 分别面向主叫和被叫:
///   _callerUdp: 接收主叫发来的 RTP, 转发到被叫
///   _calleeUdp: 接收被叫发来的 RTP, 转发到主叫
/// 
/// NAudio 可选:
///   - 解码 G.711 → 录音为 WAV
///   - 读取 WAV → 编码 G.711 → 注入 RTP 流
/// </summary>
internal class RtpRelay : IDisposable
{
    private readonly UdpClient _callerUdp;
    private readonly UdpClient _calleeUdp;
    private readonly ILogger _logger;
    private readonly RtpPortAllocator _portAllocator;
    private readonly CancellationTokenSource _cts = new();
    private Task? _callerRecvTask;
    private Task? _calleeRecvTask;

    // 远端 RTP 端点 (从 SDP 解析得到, 可能是内网 IP 不可路由)
    private IPEndPoint? _callerRemoteEP;
    private IPEndPoint? _calleeRemoteEP;

    // 地址学习: 是否已从实际 RTP 包中学习到真实远端地址
    private bool _callerEpLearned;
    private bool _calleeEpLearned;

    // 首包缓冲: 目标端点为 null 时暂存 RTP 包, 避免首包丢失
    // 对 56K 猫拨号等场景至关重要 — 握手阶段初始信号缺损可能导致连接协商失败
    private const int MAX_PENDING_PACKETS = 50; // ~1 秒 (50 × 20ms)
    private readonly ConcurrentQueue<byte[]> _pendingForCallee = new(); // 主叫→被叫方向, 等待被叫端点
    private readonly ConcurrentQueue<byte[]> _pendingForCaller = new(); // 被叫→主叫方向, 等待主叫端点

    // NAudio 录音
    private WaveFileWriter? _recordingWriter;
    private readonly object _recordingLock = new();
    private bool _disposed;

    public int CallerLocalPort { get; }
    public int CalleeLocalPort { get; }
    public bool IsRunning { get; private set; }
    public bool HasCalleeRemoteEP => _calleeRemoteEP != null;

    public RtpRelay(RtpPortAllocator portAllocator, ILogger logger)
    {
        _portAllocator = portAllocator;
        _logger = logger;

        // 分配两个偶数端口
        CallerLocalPort = portAllocator.Allocate();
        CalleeLocalPort = portAllocator.Allocate();

        var bindAddr = portAllocator.BindAddress;
        _callerUdp = new UdpClient(new IPEndPoint(bindAddr, CallerLocalPort));
        _calleeUdp = new UdpClient(new IPEndPoint(bindAddr, CalleeLocalPort));

        // 设置接收超时, 避免无限阻塞
        _callerUdp.Client.ReceiveTimeout = 5000;
        _calleeUdp.Client.ReceiveTimeout = 5000;

        // 诊断日志: 确认 UdpClient 实际绑定的端口和地址
        try
        {
            var callerLocal = _callerUdp.Client.LocalEndPoint as System.Net.IPEndPoint;
            var calleeLocal = _calleeUdp.Client.LocalEndPoint as System.Net.IPEndPoint;
            logger.LogInformation("RTP UdpClient 已绑定: 主叫侧={CallerEP}, 被叫侧={CalleeEP}",
                callerLocal, calleeLocal);
        }
        catch { }
    }

    public void SetCallerRemoteEP(IPEndPoint ep)
    {
        // 仅在未从实际 RTP 包学习到地址时才接受 SDP 端点
        // SDP 中的 IP 可能是运营商内网 IP (不可路由), 实际地址从 RTP 包源地址学习
        if (!_callerEpLearned)
        {
            _callerRemoteEP = ep;
            FlushPendingPackets(_pendingForCaller, _callerUdp, ep, "被叫→主叫");
        }
    }
    public void SetCalleeRemoteEP(IPEndPoint ep)
    {
        if (!_calleeEpLearned)
        {
            _calleeRemoteEP = ep;
            FlushPendingPackets(_pendingForCallee, _calleeUdp, ep, "主叫→被叫");
        }
    }

    /// <summary>
    /// 启动双向 RTP 转发
    /// 外呼场景可在收到 200 OK 之前就启动, 让 ReceiveLoop 监听端口
    /// 运营商发来的 RTP 包一到就能学习到真实地址
    /// </summary>
    public void StartRelay()
    {
        if (IsRunning) return;
        IsRunning = true;

        // 收到主叫的 RTP → 学习主叫的真实地址 (用于被叫→主叫方向转发目标)
        // 转发目标: _calleeRemoteEP (运营商)
        // 待发缓冲: _pendingForCallee (被叫端点未知时暂存)
        _callerRecvTask = Task.Run(() => ReceiveLoop(
            _callerUdp, _calleeUdp, () => _calleeRemoteEP, "主叫→被叫",
            () => _callerEpLearned,
            ep => { _callerRemoteEP = ep; _callerEpLearned = true; },
            _pendingForCallee));

        // 收到被叫的 RTP → 学习被叫的真实地址 (用于主叫→被叫方向转发目标)
        // 转发目标: _callerRemoteEP (主叫)
        // 待发缓冲: _pendingForCaller (主叫端点未知时暂存)
        _calleeRecvTask = Task.Run(() => ReceiveLoop(
            _calleeUdp, _callerUdp, () => _callerRemoteEP, "被叫→主叫",
            () => _calleeEpLearned,
            ep => { _calleeRemoteEP = ep; _calleeEpLearned = true; },
            _pendingForCaller));
    }

    /// <summary>
    /// RTP 接收循环: 从一侧收到包, 转发到另一侧
    /// 支持远端地址学习: 从实际 RTP 包的源地址学习真实远端 IP (解决 SDP 中内网 IP 不可路由问题)
    /// </summary>
    private async Task ReceiveLoop(UdpClient receiver, UdpClient sender,
        Func<IPEndPoint?> getDest, string direction,
        Func<bool> isEpLearned, Action<IPEndPoint> learnRemoteEP,
        ConcurrentQueue<byte[]> pendingQueue)
    {
        _logger.LogDebug("RTP 转发循环启动: {Direction}", direction);

        int recvCount = 0;
        int dropCount = 0;
        int bufferedCount = 0;
        var lastStatsTime = DateTime.UtcNow;

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var result = await receiver.ReceiveAsync().ConfigureAwait(false);

                // 远端地址学习: 从收到的第一个 RTP 包的源地址学习真实远端端点
                // 解决 SDP 中的 c= IP 是运营商内网 IP (如 172.26.160.89) 不可路由的问题
                // 关键: 必须使用实际源地址的 IP 和端口, 不能混用 SDP 端口
                // 路由器 NAT 会同时改写 IP 和端口, SDP 端口在 NAT 后已不正确
                if (!isEpLearned())
                {
                    var realEP = result.RemoteEndPoint;
                    learnRemoteEP(realEP);
                    _logger.LogInformation("RTP 地址学习: {Direction} 真实端点 = {Ip}:{Port}",
                        direction, realEP.Address, realEP.Port);
                }

                recvCount++;
                var dest = getDest();
                if (dest != null)
                {
                    // 先刷新待发缓冲包 (保持时序, 避免首包丢失)
                    FlushPendingPackets(pendingQueue, sender, dest, direction);
                    await sender.SendAsync(result.Buffer, dest).ConfigureAwait(false);

                    // NAudio 录音: 解码被叫侧音频
                    if (direction == "被叫→主叫")
                    {
                        DecodeAndRecord(result.Buffer);
                    }
                }
                else
                {
                    // 目标端点尚未知 (对端 SDP 还未到达), 暂存到缓冲队列
                    // 避免首包丢失: 56K 猫拨号等场景握手信号不能缺
                    if (pendingQueue.Count < MAX_PENDING_PACKETS)
                    {
                        pendingQueue.Enqueue(result.Buffer);
                        bufferedCount++;
                    }
                    else
                    {
                        dropCount++; // 缓冲满, 丢弃最旧的包
                    }
                }

                // 每 5 秒输出一次统计
                if (DateTime.UtcNow - lastStatsTime >= TimeSpan.FromSeconds(5))
                {
                    _logger.LogInformation("RTP 统计: {Direction} 收={Recv} 缓冲={Buffered} 丢包={Drop} 目标={Dest}",
                        direction, recvCount, bufferedCount, dropCount, dest);
                    lastStatsTime = DateTime.UtcNow;
                }
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                // 接收超时, 继续循环
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted
                                          || ex.SocketErrorCode == SocketError.OperationAborted)
            {
                // Socket 被 Dispose 中止 (正常关闭), 静默退出
                // Windows: 错误码 995 = OperationAborted; Linux: Interrupted
                break;
            }
            catch (ObjectDisposedException)
            {
                break; // Socket 已关闭
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RTP 转发异常: {Direction}", direction);
            }
        }

        _logger.LogDebug("RTP 转发循环结束: {Direction}", direction);
    }

    // ===== NAudio G.711 解码/录音 =====

    /// <summary>
    /// 解码 RTP 载荷并写入 WAV 文件
    /// 支持 PCMA (pt=8) 和 PCMU (pt=0)
    /// </summary>
    private void DecodeAndRecord(byte[] rtpPacket)
    {
        lock (_recordingLock)
        {
            if (_recordingWriter == null) return;
        }

        if (rtpPacket.Length < 12) return;

        // 解析 RTP 头
        int csrcCount = rtpPacket[0] & 0x0F;
        int headerLen = 12 + csrcCount * 4;

        // 检查是否有扩展头
        bool hasExtension = (rtpPacket[0] & 0x10) != 0;
        if (hasExtension && rtpPacket.Length > headerLen + 4)
        {
            int extLen = (rtpPacket[headerLen + 2] << 8) | rtpPacket[headerLen + 3];
            headerLen += 4 + extLen * 4;
        }

        if (rtpPacket.Length <= headerLen) return;

        byte payloadType = (byte)(rtpPacket[1] & 0x7F);
        byte[] payload = rtpPacket[headerLen..];

        // 根据编码类型解码为 16-bit PCM
        short[] pcmSamples;
        if (payloadType == 8) // PCMA (A-Law)
        {
            pcmSamples = new short[payload.Length];
            for (int i = 0; i < payload.Length; i++)
                pcmSamples[i] = ALawDecoder.ALawToLinearSample(payload[i]);
        }
        else if (payloadType == 0) // PCMU (μ-Law)
        {
            pcmSamples = new short[payload.Length];
            for (int i = 0; i < payload.Length; i++)
                pcmSamples[i] = MuLawDecoder.MuLawToLinearSample(payload[i]);
        }
        else
        {
            return; // 不支持的编码
        }

        // short[] → byte[] (16-bit PCM, little-endian)
        byte[] pcmBytes = new byte[pcmSamples.Length * 2];
        Buffer.BlockCopy(pcmSamples, 0, pcmBytes, 0, pcmBytes.Length);

        lock (_recordingLock)
        {
            try
            {
                _recordingWriter?.Write(pcmBytes, 0, pcmBytes.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RTP 录音写入失败");
            }
        }
    }

    /// <summary>
    /// 开始录音 (WAV 格式, 8000Hz 16-bit 单声道)
    /// </summary>
    public void StartRecording(string outputPath)
    {
        lock (_recordingLock)
        {
            StopRecordingInternal();
            var format = new WaveFormat(8000, 16, 1);
            _recordingWriter = new WaveFileWriter(outputPath, format);
        }
    }

    /// <summary>
    /// 停止录音
    /// </summary>
    public string? StopRecording()
    {
        lock (_recordingLock)
        {
            return StopRecordingInternal();
        }
    }

    private string? StopRecordingInternal()
    {
        if (_recordingWriter == null) return null;
        var path = _recordingWriter.Filename ?? "";
        try
        {
            _recordingWriter.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "关闭录音文件失败");
        }
        _recordingWriter = null;
        return path;
    }

    // ===== NAudio 提示音播放 =====

    private CancellationTokenSource? _promptCts;

    /// <summary>
    /// 播放提示音 (WAV 文件 → G.711 编码 → RTP 注入)
    /// </summary>
    public void PlayPrompt(string promptId, CancellationToken externalCt)
    {
        StopPrompt();
        _promptCts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = _promptCts.Token;

        // TODO: 根据 promptId 查找 WAV 文件路径
        // 当前仅支持文件路径作为 promptId
        _ = Task.Run(async () =>
        {
            try
            {
                await PlayWavAsRtp(promptId, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogError(ex, "播放提示音失败: {PromptId}", promptId);
            }
        }, ct);
    }

    public void StopPrompt()
    {
        _promptCts?.Cancel();
        _promptCts?.Dispose();
        _promptCts = null;
    }

    /// <summary>
    /// 将 WAV 文件读取、编码为 PCMA、打包成 RTP 发送到主叫侧
    /// </summary>
    private async Task PlayWavAsRtp(string wavPath, CancellationToken ct)
    {
        if (!File.Exists(wavPath)) return;

        using var reader = new WaveFileReader(wavPath);
        var format = reader.WaveFormat;

        // 确保是 8000Hz 16-bit 单声道 (G.711 要求)
        if (format.SampleRate != 8000 || format.BitsPerSample != 16 || format.Channels != 1)
        {
            _logger.LogWarning("提示音 WAV 格式不匹配: 需要 8000Hz/16bit/单声道, 实际 {Rate}/{Bits}/{Ch}",
                format.SampleRate, format.BitsPerSample, format.Channels);
            return;
        }

        uint ssrc = (uint)Random.Shared.Next();
        ushort seqNum = 0;
        uint timestamp = 0;
        const int samplesPerPacket = 160; // 20ms @ 8000Hz
        byte[] pcmBuffer = new byte[samplesPerPacket * 2]; // 16-bit = 2 bytes/sample

        while (!ct.IsCancellationRequested)
        {
            int read = await reader.ReadAsync(pcmBuffer, 0, pcmBuffer.Length, ct);
            if (read == 0) break;

            int sampleCount = read / 2;
            byte[] alawPayload = new byte[sampleCount];

            for (int i = 0; i < sampleCount; i++)
            {
                short sample = BitConverter.ToInt16(pcmBuffer, i * 2);
                alawPayload[i] = ALawEncoder.LinearToALawSample(sample);
            }

            var rtpPacket = BuildRtpPacket(ssrc, seqNum++, timestamp, 8, alawPayload);
            var dest = _callerRemoteEP;
            if (dest != null)
            {
                try
                {
                    await _callerUdp.SendAsync(rtpPacket, dest);
                }
                catch { break; }
            }

            timestamp += (uint)sampleCount;

            // 按 20ms 间隔发送
            await Task.Delay(20, ct);
        }
    }

    /// <summary>
    /// 构造 RTP 包 (最小 12 字节头 + 载荷)
    /// </summary>
    private static byte[] BuildRtpPacket(uint ssrc, ushort seqNum, uint timestamp, byte payloadType, byte[] payload)
    {
        byte[] packet = new byte[12 + payload.Length];

        // V=2, P=0, X=0, CC=0
        packet[0] = 0x80;
        // M=0, PT
        packet[1] = (byte)(payloadType & 0x7F);
        // Sequence Number
        packet[2] = (byte)(seqNum >> 8);
        packet[3] = (byte)(seqNum & 0xFF);
        // Timestamp
        packet[4] = (byte)(timestamp >> 24);
        packet[5] = (byte)(timestamp >> 16);
        packet[6] = (byte)(timestamp >> 8);
        packet[7] = (byte)(timestamp & 0xFF);
        // SSRC
        packet[8] = (byte)(ssrc >> 24);
        packet[9] = (byte)(ssrc >> 16);
        packet[10] = (byte)(ssrc >> 8);
        packet[11] = (byte)(ssrc & 0xFF);

        // Payload
        Buffer.BlockCopy(payload, 0, packet, 12, payload.Length);
        return packet;
    }

    /// <summary>
    /// 刷新待发缓冲包: 目标端点变为可用时, 将暂存的 RTP 包发送出去
    /// 由 SetCallerRemoteEP/SetCalleeRemoteEP 触发, 也在 ReceiveLoop 中目标端点可用时触发
    /// </summary>
    private void FlushPendingPackets(ConcurrentQueue<byte[]> queue, UdpClient sender, IPEndPoint dest, string direction)
    {
        int count = 0;
        while (queue.TryDequeue(out var bufferedPacket))
        {
            try
            {
                sender.Send(bufferedPacket, bufferedPacket.Length, dest);
                count++;
            }
            catch { break; } // 发送失败 (socket 可能已关闭), 停止刷新
        }
        if (count > 0)
        {
            _logger.LogInformation("RTP 缓冲刷新: {Direction} 发送 {Count} 个待发包 → {Dest}",
                direction, count, dest);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();

        try { _callerRecvTask?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        try { _calleeRecvTask?.Wait(TimeSpan.FromSeconds(3)); } catch { }

        _cts.Dispose();
        _callerUdp.Dispose();
        _calleeUdp.Dispose();

        lock (_recordingLock)
        {
            StopRecordingInternal();
        }

        StopPrompt();

        _portAllocator.Release(CallerLocalPort);
        _portAllocator.Release(CalleeLocalPort);
    }
}
