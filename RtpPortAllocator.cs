using System.Collections.Concurrent;
using System.Net;

namespace AsterTele;

/// <summary>
/// RTP 端口分配器
/// 从配置的端口范围中分配偶数端口 (RTP 约定: 偶数端口=RTP, 奇数端口=RTCP)
/// 线程安全, 支持并发分配和释放
/// </summary>
public class RtpPortAllocator
{
    private readonly int _minPort;
    private readonly int _maxPort;
    private readonly IPAddress _bindAddress;
    private readonly ConcurrentDictionary<int, bool> _allocated = new();
    private int _nextPort;
    private readonly object _lock = new();

    public RtpPortAllocator(RtpOptions options)
    {
        _minPort = options.PortRangeStart % 2 == 0 ? options.PortRangeStart : options.PortRangeStart + 1;
        _maxPort = options.PortRangeEnd;
        _bindAddress = string.IsNullOrEmpty(options.BindAddress) ? IPAddress.Any : IPAddress.Parse(options.BindAddress);
        _nextPort = _minPort;
    }

    /// <summary>
    /// 分配一个偶数 RTP 端口
    /// </summary>
    public int Allocate()
    {
        lock (_lock)
        {
            for (int attempt = 0; attempt < (_maxPort - _minPort) / 2; attempt++)
            {
                int port = _nextPort;
                _nextPort += 2;
                if (_nextPort > _maxPort)
                    _nextPort = _minPort;

                if (_allocated.TryAdd(port, true))
                    return port;
            }

            throw new InvalidOperationException($"RTP 端口范围 {_minPort}-{_maxPort} 已耗尽");
        }
    }

    /// <summary>
    /// 释放已分配的端口
    /// </summary>
    public void Release(int port)
    {
        _allocated.TryRemove(port, out _);
    }

    /// <summary>
    /// 获取绑定地址
    /// </summary>
    public IPAddress BindAddress => _bindAddress;
}
