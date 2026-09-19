using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace OmniHax;

/// <summary>
/// Diagnostic probe that allocates a fresh page in the target (never accessed by the
/// game) and optionally guards it or sets a debug register on it. Because the page
/// is never touched by the game, any reaction to the guard/DR is target-side
/// detection rather than an access. The baseline kind (allocate only) isolates
/// detection of new allocations from detection of the guard/DR.
/// </summary>
internal sealed class DecoyProbe : IAccessTracker, IDisposable
{
    private const int PageSize = 0x1000;
    private const uint StillActive = 259;
    private static readonly TimeSpan MonitorDuration = TimeSpan.FromSeconds(20);

    private readonly ProcessMemory _memory;
    private readonly DecoyKind _kind;
    private readonly ConcurrentQueue<string> _log = new();
    private readonly ConcurrentDictionary<uint, DebugRegisters> _saved = new();

    private Thread? _monitor;
    private volatile bool _running;
    private volatile bool _pageGuarded;
    private bool _disposed;
    private ulong _decoy;
    private int _failureLogCount;

    public DecoyProbe(ProcessMemory memory, DecoyKind kind)
    {
        _memory = memory;
        _kind = kind;
    }

    public bool IsRunning => _running;
    public ulong WatchedAddress => _decoy;
    public int WatchedSize => 1;
    public bool IsAligned => true;

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

        IntPtr allocated = NativeMethods.VirtualAllocEx(
            _memory.Handle,
            IntPtr.Zero,
            (IntPtr)PageSize,
            NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
            NativeMethods.PAGE_READWRITE);

        if (allocated == IntPtr.Zero)
            throw new InvalidOperationException($"VirtualAllocEx failed (err={Marshal.GetLastWin32Error()}).");

        _decoy = unchecked((ulong)allocated.ToInt64());
        Log($"decoy: allocated page 0x{_decoy:X} (kind={_kind})");

        switch (_kind)
        {
            case DecoyKind.Guard:
                if (!NativeMethods.VirtualProtectEx(
                        _memory.Handle, allocated, (IntPtr)PageSize,
                        NativeMethods.PAGE_READWRITE | NativeMethods.PAGE_GUARD, out _))
                {
                    throw new InvalidOperationException($"VirtualProtectEx(PAGE_GUARD) failed (err={Marshal.GetLastWin32Error()}).");
                }
                _pageGuarded = true;
                Log($"decoy guard: PAGE_GUARD set on page 0x{_decoy:X} (game never accesses it)");
                break;

            case DecoyKind.Dr:
                ArmAllThreads();
                Log($"decoy DR: DR0 set to 0x{_decoy:X} on all threads (game never accesses it)");
                break;
        }

        _running = true;
        _monitor = new Thread(Monitor)
        {
            IsBackground = true,
            Name = "OmniHax.DecoyProbe"
        };
        _monitor.Start();
    }

    private void ArmAllThreads()
    {
        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
        if (snapshot == IntPtr.Zero || snapshot == (IntPtr)(-1))
        {
            Log($"decoy DR: thread snapshot failed (err={Marshal.GetLastWin32Error()})");
            return;
        }

        int total = 0;
        int armed = 0;
        int failed = 0;

        try
        {
            var entry = new NativeMethods.THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>() };
            if (!NativeMethods.Thread32First(snapshot, ref entry))
                return;

            do
            {
                if (entry.th32OwnerProcessID != (uint)_memory.ProcessId)
                    continue;

                total++;
                if (ArmThread(entry.th32ThreadID))
                    armed++;
                else
                    failed++;
            }
            while (NativeMethods.Thread32Next(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        Log($"decoy DR: threads={total} armed={armed} failed={failed}");
    }

    private bool ArmThread(uint threadId)
    {
        IntPtr raw = Marshal.AllocHGlobal(1232 + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT | NativeMethods.THREAD_SUSPEND_RESUME,
            false,
            threadId);

        try
        {
            if (handle == IntPtr.Zero)
            {
                LogFailure($"OpenThread({threadId}) failed (err={Marshal.GetLastWin32Error()})");
                return false;
            }

            if (NativeMethods.SuspendThread(handle) == unchecked((uint)-1))
            {
                LogFailure($"SuspendThread({threadId}) failed (err={Marshal.GetLastWin32Error()})");
                return false;
            }

            try
            {
                var context = new NativeMethods.CONTEXT64 { ContextFlags = NativeMethods.CONTEXT_DEBUG_REGISTERS };
                Marshal.StructureToPtr(context, aligned, false);

                if (!NativeMethods.GetThreadContext(handle, aligned))
                {
                    LogFailure($"GetThreadContext({threadId}) failed (err={Marshal.GetLastWin32Error()})");
                    return false;
                }

                context = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);
                _saved[threadId] = new DebugRegisters(context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr7);

                context.Dr0 = _decoy;
                context.Dr7 = BuildDr7(context.Dr7);

                Marshal.StructureToPtr(context, aligned, false);
                bool ok = NativeMethods.SetThreadContext(handle, aligned);
                if (!ok)
                    LogFailure($"SetThreadContext({threadId}) failed (err={Marshal.GetLastWin32Error()})");
                return ok;
            }
            finally
            {
                NativeMethods.ResumeThread(handle);
            }
        }
        finally
        {
            if (handle != IntPtr.Zero)
                NativeMethods.CloseHandle(handle);
            Marshal.FreeHGlobal(raw);
        }
    }

    private static ulong BuildDr7(ulong existingDr7)
    {
        const int slot = 0;
        ulong dr7 = existingDr7;
        dr7 |= 1UL << (2 * slot);   // local enable
        dr7 &= ~(0b11UL << 16);
        dr7 |= 0b01UL << 16;         // RW0 = write
        dr7 &= ~(0b11UL << 18);      // LEN0 = 1 byte
        dr7 |= 1UL << 10;            // reserved
        return dr7;
    }

    private void LogFailure(string message)
    {
        if (Interlocked.Increment(ref _failureLogCount) <= 20)
            Log(message);
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
                Log($"decoy {_kind}: target still running after 20s (no reaction observed)");
                _running = false;
                break;
            }

            Thread.Sleep(250);
        }
    }

    private string DescribeExit(uint code)
    {
        string reason = code == 0x00000003
            ? " (exit code 3 - UE handler / self-terminate)"
            : code == 0x80000004
                ? " (STATUS_SINGLE_STEP - a debug register fired)"
                : code == 0x80000001
                    ? " (STATUS_GUARD_PAGE_VIOLATION)"
                    : string.Empty;

        return $"decoy {_kind}: target exited, exitCode=0x{code:X8}{reason}";
    }

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

        if (_kind == DecoyKind.Dr)
            RestoreAllThreads();

        if (_pageGuarded)
        {
            NativeMethods.VirtualProtectEx(
                _memory.Handle, unchecked((IntPtr)(long)_decoy), (IntPtr)PageSize, NativeMethods.PAGE_READWRITE, out _);
            _pageGuarded = false;
        }

        if (_decoy != 0)
        {
            NativeMethods.VirtualFreeEx(_memory.Handle, unchecked((IntPtr)(long)_decoy), IntPtr.Zero, NativeMethods.MEM_RELEASE);
            Log($"decoy: freed page 0x{_decoy:X}");
            _decoy = 0;
        }

        _monitor = null;
    }

    private void RestoreAllThreads()
    {
        foreach (KeyValuePair<uint, DebugRegisters> entry in _saved)
            RestoreThread(entry.Key, entry.Value);
    }

    private void RestoreThread(uint threadId, DebugRegisters original)
    {
        IntPtr raw = Marshal.AllocHGlobal(1232 + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT | NativeMethods.THREAD_SUSPEND_RESUME,
            false,
            threadId);

        try
        {
            if (handle == IntPtr.Zero)
                return;

            if (NativeMethods.SuspendThread(handle) == unchecked((uint)-1))
                return;

            try
            {
                var context = new NativeMethods.CONTEXT64 { ContextFlags = NativeMethods.CONTEXT_DEBUG_REGISTERS };
                Marshal.StructureToPtr(context, aligned, false);

                if (NativeMethods.GetThreadContext(handle, aligned))
                {
                    context = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);
                    context.Dr0 = original.Dr0;
                    context.Dr1 = original.Dr1;
                    context.Dr2 = original.Dr2;
                    context.Dr3 = original.Dr3;
                    context.Dr7 = original.Dr7;
                    Marshal.StructureToPtr(context, aligned, false);
                    NativeMethods.SetThreadContext(handle, aligned);
                }
            }
            finally
            {
                NativeMethods.ResumeThread(handle);
            }
        }
        finally
        {
            if (handle != IntPtr.Zero)
                NativeMethods.CloseHandle(handle);
            Marshal.FreeHGlobal(raw);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Stop();
    }
}
