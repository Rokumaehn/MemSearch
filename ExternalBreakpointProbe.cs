using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace MemSearch;

/// <summary>
/// Diagnostic probe that sets a hardware breakpoint from outside the target without
/// attaching a debugger. Used to determine whether the target detects debug
/// registers (self-read) and whether external thread arming is permitted.
/// The breakpoint is never handled, so if the watched address is written the
/// target will terminate with STATUS_SINGLE_STEP, and if it detects the DRs it
/// will terminate itself.
/// </summary>
internal sealed class ExternalBreakpointProbe : IAccessTracker, IDisposable
{
    private const int ContextSize = 1232;
    private const int MaxIndividualFailureLogs = 20;
    private const uint StillActive = 259;
    private static readonly TimeSpan MonitorDuration = TimeSpan.FromSeconds(20);

    private readonly ProcessMemory _memory;
    private readonly ulong _watchAddress;
    private readonly int _size;
    private readonly ConcurrentQueue<string> _log = new();
    private readonly ConcurrentDictionary<uint, DebugRegisters> _original = new();

    private Thread? _monitor;
    private volatile bool _running;
    private bool _disposed;

    public ExternalBreakpointProbe(ProcessMemory memory, ulong address, int size)
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

        _running = true;
        Log($"external-DR probe (no debugger): watching 0x{_watchAddress:X} size={_size}");
        ArmAllThreads();

        _monitor = new Thread(Monitor)
        {
            IsBackground = true,
            Name = "MemSearch.ExternalProbe"
        };
        _monitor.Start();
    }

    private void ArmAllThreads()
    {
        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
        if (snapshot == IntPtr.Zero || snapshot == (IntPtr)(-1))
        {
            Log($"thread snapshot failed (err={Marshal.GetLastWin32Error()})");
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

        Log($"external-DR probe: threads={total} armed={armed} failed={failed}");
    }

    private bool ArmThread(uint threadId)
    {
        IntPtr raw = Marshal.AllocHGlobal(ContextSize + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT | NativeMethods.THREAD_SUSPEND_RESUME,
            false,
            threadId);

        bool succeeded = false;

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
                _original[threadId] = new DebugRegisters(context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr7);

                context.Dr0 = _watchAddress;
                context.Dr7 = BuildDr7(context.Dr7);

                Marshal.StructureToPtr(context, aligned, false);
                succeeded = NativeMethods.SetThreadContext(handle, aligned);

                if (!succeeded)
                    LogFailure($"SetThreadContext({threadId}) failed (err={Marshal.GetLastWin32Error()})");
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

        return succeeded;
    }

    private ulong BuildDr7(ulong existingDr7)
    {
        ulong len = _size switch
        {
            2 => 0b01UL,
            4 => 0b11UL,
            8 => 0b10UL,
            _ => 0b00UL
        };

        const int slot = 0;
        ulong dr7 = existingDr7;
        dr7 |= 1UL << (2 * slot);                    // local enable
        dr7 &= ~(0b11UL << 16);
        dr7 |= 0b01UL << 16;                          // RW0 = write
        dr7 &= ~(0b11UL << 18);
        dr7 |= len << 18;                             // LEN0
        dr7 |= 1UL << 10;                             // reserved
        return dr7;
    }

    private int _failureLogCount;

    private void LogFailure(string message)
    {
        if (Interlocked.Increment(ref _failureLogCount) <= MaxIndividualFailureLogs)
            Log(message);
    }

    private void Monitor()
    {
        DateTime deadline = DateTime.UtcNow + MonitorDuration;

        while (_running)
        {
            if (NativeMethods.GetExitCodeProcess(_memory.Handle, out uint exitCode) && exitCode != StillActive)
            {
                Log($"external-DR probe: target exited, exitCode=0x{exitCode:X8}");
                _running = false;
                break;
            }

            if (DateTime.UtcNow >= deadline)
            {
                Log("external-DR probe: target still running after 20s (no exit observed)");
                _running = false;
                break;
            }

            Thread.Sleep(250);
        }
    }

    private void RestoreAllThreads()
    {
        foreach (KeyValuePair<uint, DebugRegisters> entry in _original)
            RestoreThread(entry.Key, entry.Value);
    }

    private void RestoreThread(uint threadId, DebugRegisters original)
    {
        IntPtr raw = Marshal.AllocHGlobal(ContextSize + 16);
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

        RestoreAllThreads();
        _monitor = null;
        Log("external-DR probe: cleared debug registers");
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Stop();
    }
}
