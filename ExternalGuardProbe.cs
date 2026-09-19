using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace OmniHax;

/// <summary>
/// Diagnostic probe that sets PAGE_GUARD on the watched address's page from outside
/// the target, with no debugger and no debug registers, and observes what happens.
/// Used to determine whether the target detects page-protection changes.
/// </summary>
internal sealed class ExternalGuardProbe : IAccessTracker, IDisposable
{
    private const int PageSize = 0x1000;
    private const uint StillActive = 259;
    private static readonly TimeSpan MonitorDuration = TimeSpan.FromSeconds(20);

    private readonly ProcessMemory _memory;
    private readonly ulong _watchAddress;
    private readonly int _size;
    private readonly ConcurrentQueue<string> _log = new();

    private Thread? _monitor;
    private volatile bool _running;
    private volatile bool _guardArmed;
    private ulong _pageBase;
    private uint _originalProtect;
    private bool _disposed;

    public ExternalGuardProbe(ProcessMemory memory, ulong address, int size)
    {
        _memory = memory;
        _size = Math.Clamp(size <= 0 ? 4 : size, 1, 8);
        _watchAddress = address & ~((ulong)_size - 1);
        IsAligned = _watchAddress == address;
    }

    public bool IsRunning => _running;
    public ulong WatchedAddress => _watchAddress;
    public int WatchedSize => _size;
    public bool IsAligned { get; }

    public IReadOnlyCollection<AccessHit> GetHits() => Array.Empty<AccessHit>();

    public void ClearHits() { }

    public IReadOnlyList<string> DrainLog()
    {
        var lines = new List<string>();
        while (_log.TryDequeue(out string? line))
            lines.Add(line);
        return lines;
    }

    private void Log(string message)
    {
        _log.Enqueue($"{DateTime.Now:HH:mm:ss.fff} {message}");
        while (_log.Count > 4000)
            _log.TryDequeue(out _);
        HardwareBreakpointTracker.Trace?.Invoke(message);
    }

    public void Start()
    {
        if (_running)
            return;

        if (!_memory.Is64BitProcess)
            throw new NotSupportedException("Access tracking is only supported for 64-bit target processes.");

        ulong pageBase = _watchAddress & ~0xFFFUL;
        int mbiSize = Marshal.SizeOf<NativeMethods.MEMORY_BASIC_INFORMATION>();

        IntPtr queried = NativeMethods.VirtualQueryEx(
            _memory.Handle, unchecked((IntPtr)(long)pageBase), out NativeMethods.MEMORY_BASIC_INFORMATION mbi, (IntPtr)mbiSize);

        if (queried == IntPtr.Zero)
            throw new InvalidOperationException($"VirtualQueryEx failed at 0x{pageBase:X} (err={Marshal.GetLastWin32Error()}).");

        if (mbi.State != NativeMethods.MEM_COMMIT)
            throw new InvalidOperationException($"Page 0x{pageBase:X} is not committed (state=0x{mbi.State:X}).");

        _pageBase = pageBase;
        _originalProtect = mbi.Protect;

        if (!NativeMethods.VirtualProtectEx(
                _memory.Handle, unchecked((IntPtr)(long)pageBase), (IntPtr)PageSize,
                mbi.Protect | NativeMethods.PAGE_GUARD, out _))
        {
            throw new InvalidOperationException($"VirtualProtectEx(PAGE_GUARD) failed at 0x{pageBase:X} (err={Marshal.GetLastWin32Error()}).");
        }

        _guardArmed = true;
        _running = true;
        Log($"external guard probe (no debugger): watching page 0x{pageBase:X} " +
            $"(protect=0x{mbi.Protect:X} + PAGE_GUARD) for 0x{_watchAddress:X}");

        _monitor = new Thread(Monitor)
        {
            IsBackground = true,
            Name = "OmniHax.ExternalGuardProbe"
        };
        _monitor.Start();
    }

    private void Monitor()
    {
        DateTime deadline = DateTime.UtcNow + MonitorDuration;

        while (_running)
        {
            if (NativeMethods.GetExitCodeProcess(_memory.Handle, out uint exitCode) && exitCode != StillActive)
            {
                Log(DescribeExit(exitCode));
                _running = false;
                break;
            }

            if (DateTime.UtcNow >= deadline)
            {
                Log("external guard probe: target still running after 20s (no exit observed)");
                _running = false;
                break;
            }

            Thread.Sleep(250);
        }
    }

    private static string DescribeExit(uint code) => code switch
    {
        0x80000001 => "external guard probe: target exited, exitCode=0x80000001 (STATUS_GUARD_PAGE_VIOLATION - the page was accessed and the guard fired unhandled)",
        0x00000003 => "external guard probe: target exited, exitCode=0x00000003 (self-terminated - page-protection change detected)",
        _ => $"external guard probe: target exited, exitCode=0x{code:X8}"
    };

    public void Stop()
    {
        if (!_running && _monitor is null)
            return;

        _running = false;

        Thread? monitor = _monitor;
        if (monitor is not null && monitor.IsAlive)
        {
            try
            {
                monitor.Join(1000);
            }
            catch (Exception)
            {
                // ignore
            }
        }

        RemoveGuard();
        _monitor = null;
    }

    private void RemoveGuard()
    {
        if (!_guardArmed)
            return;

        bool removed = NativeMethods.VirtualProtectEx(
            _memory.Handle, unchecked((IntPtr)(long)_pageBase), (IntPtr)PageSize, _originalProtect, out _);

        Log(removed
            ? $"external guard probe: removed guard from page 0x{_pageBase:X} (restored protect=0x{_originalProtect:X})"
            : $"external guard probe: failed to remove guard from 0x{_pageBase:X} (err={Marshal.GetLastWin32Error()})");

        _guardArmed = false;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Stop();
    }
}
