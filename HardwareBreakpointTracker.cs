using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Iced.Intel;

namespace MemSearch;

internal enum AccessKind
{
    Read,
    Write,
    ReadWrite,
    Execute
}

internal sealed class AccessHit : INotifyPropertyChanged
{
    private string _disassembly;
    private int _count;

    public AccessHit(ulong instructionAddress, uint threadId, AccessKind kind, string disassembly, byte[] bytes, ulong effectiveAddress)
    {
        InstructionAddress = instructionAddress;
        ThreadId = threadId;
        Kind = kind;
        _disassembly = disassembly;
        Bytes = bytes;
        EffectiveAddress = effectiveAddress;
        _count = 1;
    }

    public ulong InstructionAddress { get; }
    public uint ThreadId { get; }
    public AccessKind Kind { get; }
    public byte[] Bytes { get; }
    public ulong EffectiveAddress { get; }

    public string EffectiveAddressText => EffectiveAddress == 0 ? "?" : $"0x{EffectiveAddress:X}";

    public string Disassembly
    {
        get => _disassembly;
        set
        {
            if (_disassembly == value)
                return;
            _disassembly = value;
            OnPropertyChanged(nameof(Disassembly));
        }
    }

    public int Count
    {
        get => _count;
        set
        {
            if (_count == value)
                return;
            _count = value;
            OnPropertyChanged(nameof(Count));
        }
    }

    public string AddressText => $"0x{InstructionAddress:X}";
    public string KindText => Kind switch
    {
        AccessKind.Read => "Read",
        AccessKind.Write => "Write",
        AccessKind.ReadWrite => "Read/Write",
        _ => "Execute"
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged(string name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>
/// Attaches to the target as a debugger and uses a hardware breakpoint (a free
/// DR0-DR3 slot) to observe what code reads, writes or executes one address.
/// </summary>
internal sealed class HardwareBreakpointTracker : IAccessTracker, IDisposable
{
    private const int ContextSize = 1232;
    private const uint ContextAll =
        NativeMethods.CONTEXT_DEBUG_REGISTERS | NativeMethods.CONTEXT_INTEGER | NativeMethods.CONTEXT_CONTROL;

    // Cap on page-guard execute single-steps while advancing toward the watched
    // instruction; prevents hanging a busy page.
    private const long MaxGuardExecuteSteps = 200_000;

    private readonly ProcessMemory _memory;
    private readonly DisassemblyService _disassembly;
    private readonly ulong _address;
    private readonly ulong _watchAddress;
    private readonly AccessKind _mode;
    private readonly int _size;
    private readonly bool _setBreakpoints;
    private readonly AccessMechanism _mechanism;
    private readonly ConcurrentDictionary<ulong, AccessHit> _hits = new();
    private readonly ConcurrentDictionary<uint, DebugRegisters> _saved = new();
    private readonly ConcurrentDictionary<uint, int> _threadSlots = new();
    private readonly ConcurrentDictionary<uint, byte> _seenThreads = new();
    private readonly ConcurrentDictionary<uint, byte> _pendingSingleStep = new();
    private readonly ConcurrentQueue<string> _log = new();
    private readonly List<(ulong Base, ulong End, string Name)> _modules = new();
    private readonly ManualResetEventSlim _loopExited = new(false);

    private Thread? _thread;
    private volatile bool _running;
    private volatile bool _attached;
    private Exception? _attachError;
    private int _cleanupDone;
    private int _usedSlotMask;
    private bool _initialBreakpointHandled;
    private uint _remoteBreakThreadId;
    private int _armedCount;
    private int _armFailCount;
    private int _hiddenFlagCount;
    private int _lastScanUnseen = -1;
    private int _lastScanHidden = -1;
    private int _lastScanQueryFailed = -1;
    private readonly ConcurrentDictionary<uint, byte> _loggedHiddenThreads = new();
    private ulong _pageBase;
    private int _pageSize = 0x1000;
    private uint _originalProtect;
    private volatile bool _guardArmed;
    private int _guardViolationCount;
    private int _guardRearmCount;
    private long _guardExecuteSteps;
    private bool _disposed;

    public HardwareBreakpointTracker(ProcessMemory memory, DisassemblyService disassembly, ulong address,
        AccessKind mode, int size, bool setBreakpoints = true,
        AccessMechanism mechanism = AccessMechanism.HardwareBreakpoints)
    {
        _memory = memory;
        _disassembly = disassembly;
        _address = address;
        _mode = mode;
        _setBreakpoints = setBreakpoints;
        _mechanism = mechanism;

        if (mode == AccessKind.Execute)
        {
            _size = 1;
            _watchAddress = address;
        }
        else
        {
            _size = Math.Clamp(size, 1, 8);

            // Hardware data breakpoints require the address to be aligned to the
            // watched length. Align down so we never program an illegal breakpoint,
            // which is undefined behaviour and can crash the target.
            _watchAddress = address & ~((ulong)_size - 1);
        }
    }

    public bool IsRunning => _running;
    public uint ProcessId => (uint)_memory.ProcessId;
    public AccessKind Mode => _mode;
    public ulong WatchedAddress => _watchAddress;
    public int WatchedSize => _size;
    public bool IsAligned => _watchAddress == _address;
    public event Action? HitsChanged;

    public static Action<string>? Trace { get; set; }

    public IReadOnlyCollection<AccessHit> GetHits() =>
        _hits.Values.OrderBy(h => h.InstructionAddress).ToList();

    public void ClearHits() => _hits.Clear();

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
        Trace?.Invoke(message);
    }

    public void Start()
    {
        if (_running)
            return;

        if (!_memory.Is64BitProcess)
            throw new NotSupportedException("Access tracking is only supported for 64-bit target processes.");

        LoadModules();

        _loopExited.Reset();
        _running = true;
        _attached = false;
        _attachError = null;

        using var ready = new ManualResetEventSlim(false);
        _thread = new Thread(() => DebugLoop(ready))
        {
            IsBackground = true,
            Name = "MemSearch.Debugger"
        };
        _thread.Start();

        ready.Wait(TimeSpan.FromSeconds(5));

        if (_attachError is not null)
        {
            _running = false;
            throw new Win32Exception(Marshal.GetLastWin32Error(), _attachError.Message);
        }

        if (!_attached)
        {
            _running = false;
            throw new InvalidOperationException("Timed out while attaching the debugger.");
        }

        if (_mechanism == AccessMechanism.GuardPage)
        {
            try
            {
                ArmGuardPage();
            }
            catch
            {
                Stop();
                throw;
            }
        }
    }

    private void LoadModules()
    {
        try
        {
            using Process process = Process.GetProcessById(_memory.ProcessId);
            foreach (ProcessModule module in process.Modules)
            {
                ulong start = unchecked((ulong)module.BaseAddress.ToInt64());
                ulong end = start + (ulong)module.ModuleMemorySize;
                _modules.Add((start, end, module.ModuleName));
            }

            _modules.Sort((a, b) => a.Base.CompareTo(b.Base));
        }
        catch (Exception ex)
        {
            Log($"module enumeration failed: {ex.Message}");
        }
    }

    private string Describe(ulong address)
    {
        foreach ((ulong start, ulong end, string name) in _modules)
        {
            if (address >= start && address < end)
                return $"{name}+0x{address - start:X}";
        }

        return "?";
    }

    private static readonly int[] DiagnosticScanTimesMs = { 1200, 3200, 6000, 10000, 15000 };

    private void StartDiagnosticScans()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                int elapsed = 0;
                foreach (int time in DiagnosticScanTimesMs)
                {
                    await Task.Delay(time - elapsed);
                    elapsed = time;

                    if (!_running)
                        break;

                    ScanForHiddenThreads(elapsed);
                }
            }
            catch (Exception ex)
            {
                Log($"diagnostic scan failed: {ex.Message}");
            }
        });
    }

    private void ScanForHiddenThreads(int elapsedMs)
    {
        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
        if (snapshot == IntPtr.Zero || snapshot == (IntPtr)(-1))
        {
            Log($"thread scan: CreateToolhelp32Snapshot failed (err={Marshal.GetLastWin32Error()})");
            return;
        }

        int total = 0;
        int unseen = 0;
        int hiddenFromDebugger = 0;
        int queryFailed = 0;

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
                bool seen = _seenThreads.ContainsKey(entry.th32ThreadID);

                if (!seen)
                {
                    unseen++;
                    ProbeHiddenThread(entry.th32ThreadID);
                }

                switch (CheckHideFlag(entry.th32ThreadID))
                {
                    case true:
                        hiddenFromDebugger++;
                        if (_loggedHiddenThreads.TryAdd(entry.th32ThreadID, 1))
                            Log($"thread {entry.th32ThreadID}: hide-from-debugger=TRUE (debug-visible: {(seen ? "yes" : "no")})");
                        break;
                    case null:
                        queryFailed++;
                        break;
                }
            }
            while (NativeMethods.Thread32Next(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        Interlocked.Exchange(ref _hiddenFlagCount, hiddenFromDebugger);

        if (hiddenFromDebugger != _lastScanHidden || unseen != _lastScanUnseen || queryFailed != _lastScanQueryFailed)
        {
            _lastScanHidden = hiddenFromDebugger;
            _lastScanUnseen = unseen;
            _lastScanQueryFailed = queryFailed;

            Log($"thread scan t={elapsedMs}ms: toolhelp={total} debug-visible={_seenThreads.Count} " +
                $"unseen={unseen} hiddenFromDebugger={hiddenFromDebugger} queryFailed={queryFailed} " +
                $"armed={_armedCount} armFailed={_armFailCount}");
        }
    }

    /// <summary>Returns true (hidden), false (not hidden), or null (query unavailable).</summary>
    private static bool? CheckHideFlag(uint threadId)
    {
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_QUERY_INFORMATION | NativeMethods.THREAD_QUERY_LIMITED_INFORMATION,
            false,
            threadId);

        if (handle == IntPtr.Zero)
            return null;

        try
        {
            return NativeMethods.TryQueryThreadHidden(handle, out bool hidden) ? hidden : null;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private void ProbeHiddenThread(uint threadId)
    {
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT | NativeMethods.THREAD_SUSPEND_RESUME,
            false,
            threadId);

        if (handle == IntPtr.Zero)
        {
            Log($"hidden thread {threadId}: OpenThread failed (err={Marshal.GetLastWin32Error()})");
            return;
        }

        try
        {
            IntPtr raw = Marshal.AllocHGlobal(ContextSize + 16);
            IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);

            try
            {
                var context = new NativeMethods.CONTEXT64 { ContextFlags = NativeMethods.CONTEXT_DEBUG_REGISTERS };
                Marshal.StructureToPtr(context, aligned, false);

                if (NativeMethods.GetThreadContext(handle, aligned))
                {
                    context = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);
                    Log($"hidden thread {threadId}: OpenThread+GetThreadContext OK (dr0=0x{context.Dr0:X} dr7=0x{context.Dr7:X})");
                }
                else
                {
                    Log($"hidden thread {threadId}: GetThreadContext failed (err={Marshal.GetLastWin32Error()})");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(raw);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private void LogExitCode()
    {
        if (NativeMethods.GetExitCodeProcess(_memory.Handle, out uint exitCode))
            Log($"target process exited: exitCode=0x{exitCode:X8}");
        else
            Log($"target process exited (GetExitCodeProcess failed err={Marshal.GetLastWin32Error()})");
    }

    private void DebugLoop(ManualResetEventSlim ready)
    {
        uint processId = (uint)_memory.ProcessId;

        Privileges.EnableDebugPrivilege();

        if (!NativeMethods.DebugActiveProcess(processId))
        {
            _attachError = new Win32Exception(Marshal.GetLastWin32Error(), "Failed to attach the debugger to the target process.");
            _running = false;
            ready.Set();
            _loopExited.Set();
            return;
        }

        try
        {
            NativeMethods.DebugSetProcessKillOnExit(false);
            _attached = true;
            ready.Set();
            Log($"attached to pid {processId}; watching 0x{_watchAddress:X} size={_size} mode={_mode}");
            StartDiagnosticScans();

            int falseCount = 0;
            while (_running)
            {
                if (!NativeMethods.WaitForDebugEvent(out NativeMethods.DEBUG_EVENT debugEvent, 100))
                {
                    if (falseCount++ == 0)
                        Log($"WaitForDebugEvent returned false (err={Marshal.GetLastWin32Error()})");
                    continue;
                }

                uint status = NativeMethods.DBG_CONTINUE;

                try
                {
                    switch (debugEvent.DebugEventCode)
                    {
                        case NativeMethods.CREATE_PROCESS_DEBUG_EVENT:
                        case NativeMethods.CREATE_THREAD_DEBUG_EVENT:
                            ArmThread(debugEvent.ThreadId);
                            break;

                        case NativeMethods.EXCEPTION_DEBUG_EVENT:
                            status = HandleExceptionEvent(in debugEvent);
                            break;

                        case NativeMethods.EXIT_PROCESS_DEBUG_EVENT:
                            LogExitCode();
                            _running = false;
                            break;
                    }
                }
                catch (Exception ex)
                {
                    // Never let a decoding/handling error kill the debug thread and
                    // leave the target with active breakpoints.
                    Log($"debug event handling failed: {ex}");
                    status = NativeMethods.DBG_CONTINUE;
                }

                NativeMethods.ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, status);
            }
        }
        catch (Exception ex)
        {
            Log($"debug loop failed: {ex}");
        }
        finally
        {
            _running = false;
            CleanupTarget(restoreRegisters: true);
            _loopExited.Set();
        }
    }

    private uint HandleExceptionEvent(in NativeMethods.DEBUG_EVENT debugEvent)
    {
        ref readonly NativeMethods.EXCEPTION_RECORD record = ref debugEvent.Exception.ExceptionRecord;
        uint code = record.ExceptionCode;
        uint firstChance = debugEvent.ExceptionFirstChance;
        uint threadId = debugEvent.ThreadId;
        ulong exceptionAddress = unchecked((ulong)record.ExceptionAddress.ToInt64());

        if (_mechanism == AccessMechanism.GuardPage &&
            code == NativeMethods.STATUS_GUARD_PAGE_VIOLATION && firstChance == 1)
        {
            // For guard-page (#PF) exceptions, ExceptionInformation[0] is the access
            // type (read/write/execute) and [1] is the faulting address.
            ulong info0 = unchecked((ulong)record.ExceptionInformation0);
            ulong info1 = unchecked((ulong)record.ExceptionInformation1);
            ulong faultAddress = info1 >= 0x10000 ? info1 : info0;

            if (faultAddress >= _pageBase && faultAddress < _pageBase + (ulong)_pageSize)
                return HandleGuardViolation(threadId, exceptionAddress);

            // Some other guard page (e.g. the target's stack): leave it to the target.
        }

        if (code == NativeMethods.EXCEPTION_SINGLE_STEP && firstChance == 1)
        {
            if (threadId == _remoteBreakThreadId)
            {
                // The debugger's own attach thread can raise a single-step while
                // tearing down; it is not the target's code.
                Log($"swallowed remote-break thread single-step: tid={threadId}");
                return NativeMethods.DBG_CONTINUE;
            }

            if (_mechanism == AccessMechanism.GuardPage)
            {
                if (_pendingSingleStep.TryRemove(threadId, out _))
                {
                    RearmGuardPage();
                    return NativeMethods.DBG_CONTINUE;
                }

                Log($"guard: foreign single-step passed: tid={threadId} rip=0x{exceptionAddress:X} ({Describe(exceptionAddress)})");
                return NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
            }

            if (TryGetContext(threadId, ContextAll, out NativeMethods.CONTEXT64 context) &&
                IsOurAccess(threadId, in context, out ResolvedAccess access))
            {
                RecordHit(in access, threadId);
                return NativeMethods.DBG_CONTINUE;
            }

            Log($"foreign single-step passed: tid={threadId} rip=0x{exceptionAddress:X} ({Describe(exceptionAddress)})");
            return NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
        }

        if (code == NativeMethods.EXCEPTION_BREAKPOINT && !_initialBreakpointHandled)
        {
            // The OS injects ntdll!DbgUiRemoteBreakin on attach and it raises an
            // initial breakpoint that the debugger must swallow. Later breakpoints
            // belong to the target and are passed through.
            _initialBreakpointHandled = true;
            _remoteBreakThreadId = threadId;
            Log($"handled initial attach breakpoint: tid={threadId} rip=0x{exceptionAddress:X} ({Describe(exceptionAddress)})");
            return NativeMethods.DBG_CONTINUE;
        }

        LogException(in record, firstChance, threadId);
        return NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
    }

    private uint HandleGuardViolation(uint threadId, ulong exceptionAddress)
    {
        if (!TryGetContext(threadId, ContextAll, out NativeMethods.CONTEXT64 context))
        {
            Log($"guard: GetThreadContext({threadId}) failed");
            return NativeMethods.DBG_CONTINUE;
        }

        bool ours = IsOurAccess(threadId, in context, out ResolvedAccess access);
        if (ours)
            RecordHit(in access, threadId);

        if (Interlocked.Increment(ref _guardViolationCount) <= 20)
            Log($"guard violation: tid={threadId} rip=0x{context.Rip:X} ({Describe(context.Rip)})");

        // Execute watches are one-shot: once the watched instruction has run, stop
        // observing so we don't single-step the whole page afterwards.
        if (_mode == AccessKind.Execute && ours)
        {
            Log("guard: execute hit recorded; guard disarmed (one-shot)");
            DisarmGuardPage();
            return NativeMethods.DBG_CONTINUE;
        }

        // Advance past the current instruction and re-arm. Guard execute faults are
        // page-granular, so this single-steps code on the page until the watched
        // instruction runs; cap it to avoid hanging a busy page.
        if (_mode == AccessKind.Execute &&
            Interlocked.Increment(ref _guardExecuteSteps) > MaxGuardExecuteSteps)
        {
            Log($"guard: execute cap reached ({MaxGuardExecuteSteps} single-steps); disarming");
            DisarmGuardPage();
            return NativeMethods.DBG_CONTINUE;
        }

        // The OS cleared the guard bit for the page, so the faulting instruction can
        // run now. Single-step it and re-arm the guard afterwards.
        if (TrySetTrapFlag(threadId, in context))
            _pendingSingleStep[threadId] = 1;
        else
            RearmGuardPage();

        return NativeMethods.DBG_CONTINUE;
    }

    private static bool TrySetTrapFlag(uint threadId, in NativeMethods.CONTEXT64 context)
    {
        return ModifyTrapFlag(threadId, in context, set: true);
    }

    private static bool ClearTrapFlag(uint threadId)
    {
        if (!TryGetContext(threadId, NativeMethods.CONTEXT_CONTROL, out NativeMethods.CONTEXT64 context))
            return false;
        return ModifyTrapFlag(threadId, in context, set: false);
    }

    private static bool ModifyTrapFlag(uint threadId, in NativeMethods.CONTEXT64 context, bool set)
    {
        IntPtr raw = Marshal.AllocHGlobal(ContextSize + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT,
            false,
            threadId);

        try
        {
            if (handle == IntPtr.Zero)
                return false;

            NativeMethods.CONTEXT64 updated = context;
            updated.ContextFlags = NativeMethods.CONTEXT_CONTROL;
            updated.EFlags = set ? updated.EFlags | 0x100u : updated.EFlags & ~0x100u;

            Marshal.StructureToPtr(updated, aligned, false);
            return NativeMethods.SetThreadContext(handle, aligned);
        }
        finally
        {
            if (handle != IntPtr.Zero)
                NativeMethods.CloseHandle(handle);
            Marshal.FreeHGlobal(raw);
        }
    }

    private void ArmGuardPage()
    {
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
                _memory.Handle, unchecked((IntPtr)(long)pageBase), (IntPtr)_pageSize,
                mbi.Protect | NativeMethods.PAGE_GUARD, out _))
        {
            throw new InvalidOperationException($"VirtualProtectEx(PAGE_GUARD) failed at 0x{pageBase:X} (err={Marshal.GetLastWin32Error()}).");
        }

        _guardArmed = true;
        Interlocked.Exchange(ref _guardExecuteSteps, 0);
        Log($"guard: watching page 0x{pageBase:X} (protect=0x{mbi.Protect:X} + PAGE_GUARD) for 0x{_watchAddress:X}");
    }

    private void RearmGuardPage()
    {
        if (!_guardArmed)
            return;

        if (NativeMethods.VirtualProtectEx(
                _memory.Handle, unchecked((IntPtr)(long)_pageBase), (IntPtr)_pageSize,
                _originalProtect | NativeMethods.PAGE_GUARD, out _))
        {
            if (Interlocked.Increment(ref _guardRearmCount) <= 5)
                Log($"guard: re-armed page 0x{_pageBase:X}");
        }
        else
        {
            Log($"guard: re-arm failed on page 0x{_pageBase:X} (err={Marshal.GetLastWin32Error()})");
        }
    }

    private void DisarmGuardPage()
    {
        foreach (uint threadId in _pendingSingleStep.Keys)
            ClearTrapFlag(threadId);
        _pendingSingleStep.Clear();

        if (!_guardArmed)
            return;

        bool removed = NativeMethods.VirtualProtectEx(
            _memory.Handle, unchecked((IntPtr)(long)_pageBase), (IntPtr)_pageSize, _originalProtect, out _);

        Log(removed
            ? $"guard: removed from page 0x{_pageBase:X} (restored protect=0x{_originalProtect:X})"
            : $"guard: failed to remove from page 0x{_pageBase:X} (err={Marshal.GetLastWin32Error()})");

        _guardArmed = false;
    }

    private void LogException(in NativeMethods.EXCEPTION_RECORD record, uint firstChance, uint threadId)
    {
        ulong address = unchecked((ulong)record.ExceptionAddress.ToInt64());
        string extra = string.Empty;

        if (record.ExceptionCode is NativeMethods.STATUS_ACCESS_VIOLATION or NativeMethods.STATUS_GUARD_PAGE_VIOLATION)
        {
            string op = record.ExceptionInformation0 switch
            {
                0 => "read",
                1 => "write",
                8 => "execute",
                _ => $"op={record.ExceptionInformation0}"
            };
            ulong fault = unchecked((ulong)record.ExceptionInformation1);
            extra = $" {op} fault=0x{fault:X} ({Describe(fault)})";
        }

        Log($"EXCEPTION code=0x{record.ExceptionCode:X8} first={firstChance} tid={threadId} " +
            $"at=0x{address:X} ({Describe(address)}){extra}");
    }

    private sealed record ResolvedAccess(DisassembledInstruction Instruction, AccessKind Kind, ulong EffectiveAddress);

    private bool IsOurAccess(uint threadId, in NativeMethods.CONTEXT64 context, out ResolvedAccess access)
    {
        access = null!;
        ulong reported = context.Rip;

        if (_mode == AccessKind.Execute)
        {
            if (reported == _watchAddress)
            {
                DisassembledInstruction? at = DecodeAt(reported);
                if (at is not null)
                {
                    access = new ResolvedAccess(at, AccessKind.Execute, reported);
                    return true;
                }
            }

            return false;
        }

        var candidates = new List<DisassembledInstruction>();
        candidates.AddRange(_disassembly.DecodeEndingAt(_memory, reported).Where(c => !c.Instruction.IsInvalid));
        DisassembledInstruction? forward = DecodeAt(reported);
        if (forward is not null)
            candidates.Add(forward);

        var factory = new InstructionInfoFactory();

        foreach (DisassembledInstruction candidate in candidates)
        {
            ref readonly InstructionInfo info = ref factory.GetInfo(candidate.Instruction);

            foreach (UsedMemory memory in info.GetUsedMemory())
            {
                if (!MatchesMode(memory.Access))
                    continue;

                if (!RegisterAddress.TryCompute(memory, in context, out ulong effectiveAddress))
                    continue;

                if (!RegisterAddress.Overlaps(effectiveAddress, memory, _watchAddress, _size))
                    continue;

                access = new ResolvedAccess(candidate, ClassifyAccess(memory.Access, _mode), effectiveAddress);
                return true;
            }
        }

        // Address resolution can fail (e.g. FS/GS-relative operands). Fall back to
        // the DR6 status bit for the slots we programmed.
        if (_usedSlotMask != 0 && (context.Dr6 & unchecked((ulong)_usedSlotMask)) != 0)
        {
            DisassembledInstruction? best = candidates
                .OrderByDescending(c => ScoreAccess(c.Instruction))
                .ThenByDescending(c => c.Length)
                .FirstOrDefault();

            if (best is not null)
            {
                access = new ResolvedAccess(best, Classify(best.Instruction, _mode), _watchAddress);
                return true;
            }
        }

        return false;
    }

    private DisassembledInstruction? DecodeAt(ulong address)
    {
        byte[] raw = _memory.ReadBytes(address, 15) ?? Array.Empty<byte>();
        List<DisassembledInstruction> list = _disassembly.Decode(raw, address, 1);
        return list.Count > 0 && !list[0].Instruction.IsInvalid ? list[0] : null;
    }

    private bool MatchesMode(OpAccess access)
    {
        bool read = access is OpAccess.Read or OpAccess.CondRead or OpAccess.ReadWrite or OpAccess.ReadCondWrite;
        bool write = access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite;

        return _mode switch
        {
            AccessKind.Write => write,
            AccessKind.Read => read,
            _ => read || write
        };
    }

    private static AccessKind ClassifyAccess(OpAccess access, AccessKind fallback)
    {
        bool read = access is OpAccess.Read or OpAccess.CondRead or OpAccess.ReadWrite or OpAccess.ReadCondWrite;
        bool write = access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite;

        if (read && write)
            return AccessKind.ReadWrite;
        if (write)
            return AccessKind.Write;
        if (read)
            return AccessKind.Read;
        return fallback;
    }

    private void RecordHit(in ResolvedAccess access, uint threadId)
    {
        DisassembledInstruction instruction = access.Instruction;
        AccessKind kind = access.Kind;
        ulong effectiveAddress = access.EffectiveAddress;

        _hits.AddOrUpdate(
            instruction.Address,
            _ => new AccessHit(instruction.Address, threadId, kind, instruction.Text, instruction.Bytes, effectiveAddress),
            (_, existing) =>
            {
                existing.Count++;
                if (!string.IsNullOrEmpty(instruction.Text))
                    existing.Disassembly = instruction.Text;
                return existing;
            });

        Log($"hit {kind} at 0x{instruction.Address:X} ({Describe(instruction.Address)}) " +
            $"accessing 0x{effectiveAddress:X}: {instruction.Text}");

        HitsChanged?.Invoke();
    }

    private void ArmThread(uint threadId)
    {
        // Remember every thread the debugger reported, even if arming fails, so we
        // can later tell which Toolhelp threads were hidden from the debugger.
        _seenThreads[threadId] = 1;

        if (_mechanism == AccessMechanism.GuardPage || !_setBreakpoints)
            return;

        IntPtr raw = Marshal.AllocHGlobal(ContextSize + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT | NativeMethods.THREAD_SUSPEND_RESUME,
            false,
            threadId);

        try
        {
            if (handle == IntPtr.Zero)
            {
                Interlocked.Increment(ref _armFailCount);
                Log($"OpenThread({threadId}) failed (err={Marshal.GetLastWin32Error()})");
                return;
            }

            var context = new NativeMethods.CONTEXT64 { ContextFlags = NativeMethods.CONTEXT_DEBUG_REGISTERS };
            Marshal.StructureToPtr(context, aligned, false);

            if (!NativeMethods.GetThreadContext(handle, aligned))
            {
                Interlocked.Increment(ref _armFailCount);
                Log($"GetThreadContext({threadId}) failed (err={Marshal.GetLastWin32Error()})");
                return;
            }

            context = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);

            // Remember the thread's original debug registers so they can be restored.
            _saved[threadId] = new DebugRegisters(context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr7);

            int slot = FindFreeSlot(context.Dr7);
            if (slot < 0)
            {
                Interlocked.Increment(ref _armFailCount);
                Log($"thread {threadId}: no free DR slot (dr7=0x{context.Dr7:X}); not armed");
                return;
            }

            switch (slot)
            {
                case 0: context.Dr0 = _watchAddress; break;
                case 1: context.Dr1 = _watchAddress; break;
                case 2: context.Dr2 = _watchAddress; break;
                default: context.Dr3 = _watchAddress; break;
            }

            context.Dr7 = BuildDr7ForSlot(context.Dr7, slot);

            Marshal.StructureToPtr(context, aligned, false);
            bool set = NativeMethods.SetThreadContext(handle, aligned);

            _threadSlots[threadId] = slot;
            Interlocked.Or(ref _usedSlotMask, 1 << slot);

            if (set)
            {
                Interlocked.Increment(ref _armedCount);
            }
            else
            {
                Interlocked.Increment(ref _armFailCount);
                Log($"arm thread {threadId} SetThreadContext failed (err={Marshal.GetLastWin32Error()})");
            }
        }
        finally
        {
            if (handle != IntPtr.Zero)
                NativeMethods.CloseHandle(handle);
            Marshal.FreeHGlobal(raw);
        }
    }

    private static int FindFreeSlot(ulong dr7)
    {
        for (int slot = 0; slot < 4; slot++)
        {
            if ((dr7 & (1UL << (2 * slot))) == 0)
                return slot;
        }

        return -1;
    }

    private ulong BuildDr7ForSlot(ulong existingDr7, int slot)
    {
        ulong rw = _mode switch
        {
            AccessKind.Execute => 0b00UL, // execute
            AccessKind.Write => 0b01UL,   // write
            _ => 0b11UL                   // read or write
        };

        ulong len = _mode == AccessKind.Execute
            ? 0b00UL
            : _size switch
            {
                2 => 0b01UL,
                4 => 0b11UL,
                8 => 0b10UL,
                _ => 0b00UL
            };

        int rwShift = 16 + 4 * slot;
        int lenShift = 18 + 4 * slot;

        ulong dr7 = existingDr7;
        dr7 |= 1UL << (2 * slot);                       // local enable
        dr7 &= ~(0b11UL << rwShift);
        dr7 |= rw << rwShift;
        dr7 &= ~(0b11UL << lenShift);
        dr7 |= len << lenShift;
        dr7 |= 1UL << 10;                               // reserved, must be 1
        return dr7;
    }

    private static bool TryGetContext(uint threadId, uint flags, out NativeMethods.CONTEXT64 context)
    {
        context = default;
        IntPtr raw = Marshal.AllocHGlobal(ContextSize + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);
        IntPtr handle = NativeMethods.OpenThread(NativeMethods.THREAD_GET_CONTEXT, false, threadId);

        try
        {
            if (handle == IntPtr.Zero)
                return false;

            var buffer = new NativeMethods.CONTEXT64 { ContextFlags = flags };
            Marshal.StructureToPtr(buffer, aligned, false);

            if (!NativeMethods.GetThreadContext(handle, aligned))
                return false;

            context = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);
            return true;
        }
        finally
        {
            if (handle != IntPtr.Zero)
                NativeMethods.CloseHandle(handle);
            Marshal.FreeHGlobal(raw);
        }
    }

    private void CleanupTarget(bool restoreRegisters)
    {
        if (Interlocked.Exchange(ref _cleanupDone, 1) != 0)
            return;

        // Clear our breakpoints while still attached. DebugActiveProcessStop can
        // restore the debuggee's saved context (re-applying DRs), so clear DRs again
        // afterwards as well. Guard-page watches are removed by restoring protection.
        if (_mechanism == AccessMechanism.GuardPage)
            DisarmGuardPage();
        else
            ClearAllThreads(restoreRegisters, "pre-detach");

        try
        {
            NativeMethods.DebugActiveProcessStop((uint)_memory.ProcessId);
            Log("detached debugger");
        }
        catch (Exception ex)
        {
            Log($"failed to detach debugger: {ex.Message}");
        }

        if (_mechanism == AccessMechanism.GuardPage)
            DisarmGuardPage();
        else
            ClearAllThreads(restoreRegisters: false, "post-detach");

        _attached = false;
    }

    private void ClearAllThreads(bool restoreRegisters, string phase)
    {
        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
        if (snapshot == IntPtr.Zero || snapshot == (IntPtr)(-1))
            return;

        try
        {
            var entry = new NativeMethods.THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>() };
            if (!NativeMethods.Thread32First(snapshot, ref entry))
                return;

            do
            {
                if (entry.th32OwnerProcessID != (uint)_memory.ProcessId)
                    continue;

                DebugRegisters desired = default;
                if (restoreRegisters && _saved.TryGetValue(entry.th32ThreadID, out DebugRegisters original))
                    desired = original;

                ApplyDebugRegisters(entry.th32ThreadID, desired, phase);
            }
            while (NativeMethods.Thread32Next(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }
    }

    private void ApplyDebugRegisters(uint threadId, DebugRegisters desired, string phase)
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

                if (!NativeMethods.GetThreadContext(handle, aligned))
                    return;

                context = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);
                context.Dr0 = desired.Dr0;
                context.Dr1 = desired.Dr1;
                context.Dr2 = desired.Dr2;
                context.Dr3 = desired.Dr3;
                context.Dr7 = desired.Dr7;
                Marshal.StructureToPtr(context, aligned, false);
                NativeMethods.SetThreadContext(handle, aligned);

                if (NativeMethods.GetThreadContext(handle, aligned))
                {
                    var verify = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);
                    if (verify.Dr7 != desired.Dr7 || verify.Dr0 != desired.Dr0 || verify.Dr1 != desired.Dr1 ||
                        verify.Dr2 != desired.Dr2 || verify.Dr3 != desired.Dr3)
                    {
                        Log($"[{phase}] tid={threadId} DR mismatch: want dr7=0x{desired.Dr7:X} got 0x{verify.Dr7:X}");
                    }
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
        if (!_running && _thread is null)
            return;

        _running = false;

        bool exited = _loopExited.Wait(5000);

        Thread? thread = _thread;
        if (thread is not null && thread.IsAlive)
        {
            try
            {
                thread.Join(2000);
            }
            catch (Exception)
            {
                // Ignore; cleanup below is idempotent.
            }
        }

        CleanupTarget(restoreRegisters: exited);
        _thread = null;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Stop();
    }

    private static int ScoreAccess(in Instruction instruction)
    {
        if (instruction.IsInvalid)
            return 0;

        var factory = new InstructionInfoFactory();
        ref readonly InstructionInfo info = ref factory.GetInfo(instruction);

        bool read = false;
        bool write = false;

        foreach (UsedMemory memory in info.GetUsedMemory())
        {
            switch (memory.Access)
            {
                case OpAccess.Read:
                case OpAccess.CondRead:
                    read = true;
                    break;
                case OpAccess.Write:
                case OpAccess.CondWrite:
                    write = true;
                    break;
                case OpAccess.ReadWrite:
                case OpAccess.ReadCondWrite:
                    read = true;
                    write = true;
                    break;
            }
        }

        return (read ? 1 : 0) + (write ? 2 : 0);
    }

    private static AccessKind Classify(in Instruction instruction, AccessKind mode)
    {
        if (instruction.IsInvalid)
            return mode;

        var factory = new InstructionInfoFactory();
        ref readonly InstructionInfo info = ref factory.GetInfo(instruction);

        bool read = false;
        bool write = false;

        foreach (UsedMemory memory in info.GetUsedMemory())
        {
            switch (memory.Access)
            {
                case OpAccess.Read:
                case OpAccess.CondRead:
                    read = true;
                    break;
                case OpAccess.Write:
                case OpAccess.CondWrite:
                    write = true;
                    break;
                case OpAccess.ReadWrite:
                case OpAccess.ReadCondWrite:
                    read = true;
                    write = true;
                    break;
            }
        }

        if (read && write)
            return AccessKind.ReadWrite;
        if (write)
            return AccessKind.Write;
        if (read)
            return AccessKind.Read;

        return mode;
    }

    private static bool TryGetRegisterValue(Register register, in NativeMethods.CONTEXT64 c, out ulong value)
    {
        switch (register)
        {
            case Register.RAX: value = c.Rax; return true;
            case Register.RCX: value = c.Rcx; return true;
            case Register.RDX: value = c.Rdx; return true;
            case Register.RBX: value = c.Rbx; return true;
            case Register.RSP: value = c.Rsp; return true;
            case Register.RBP: value = c.Rbp; return true;
            case Register.RSI: value = c.Rsi; return true;
            case Register.RDI: value = c.Rdi; return true;
            case Register.R8: value = c.R8; return true;
            case Register.R9: value = c.R9; return true;
            case Register.R10: value = c.R10; return true;
            case Register.R11: value = c.R11; return true;
            case Register.R12: value = c.R12; return true;
            case Register.R13: value = c.R13; return true;
            case Register.R14: value = c.R14; return true;
            case Register.R15: value = c.R15; return true;
            case Register.RIP: value = c.Rip; return true;

            case Register.EAX: value = (uint)c.Rax; return true;
            case Register.ECX: value = (uint)c.Rcx; return true;
            case Register.EDX: value = (uint)c.Rdx; return true;
            case Register.EBX: value = (uint)c.Rbx; return true;
            case Register.ESP: value = (uint)c.Rsp; return true;
            case Register.EBP: value = (uint)c.Rbp; return true;
            case Register.ESI: value = (uint)c.Rsi; return true;
            case Register.EDI: value = (uint)c.Rdi; return true;
            case Register.R8D: value = (uint)c.R8; return true;
            case Register.R9D: value = (uint)c.R9; return true;
            case Register.R10D: value = (uint)c.R10; return true;
            case Register.R11D: value = (uint)c.R11; return true;
            case Register.R12D: value = (uint)c.R12; return true;
            case Register.R13D: value = (uint)c.R13; return true;
            case Register.R14D: value = (uint)c.R14; return true;
            case Register.R15D: value = (uint)c.R15; return true;
            case Register.EIP: value = (uint)c.Rip; return true;

            case Register.AX: value = (ushort)c.Rax; return true;
            case Register.CX: value = (ushort)c.Rcx; return true;
            case Register.DX: value = (ushort)c.Rdx; return true;
            case Register.BX: value = (ushort)c.Rbx; return true;
            case Register.SP: value = (ushort)c.Rsp; return true;
            case Register.BP: value = (ushort)c.Rbp; return true;
            case Register.SI: value = (ushort)c.Rsi; return true;
            case Register.DI: value = (ushort)c.Rdi; return true;
            case Register.R8W: value = (ushort)c.R8; return true;
            case Register.R9W: value = (ushort)c.R9; return true;
            case Register.R10W: value = (ushort)c.R10; return true;
            case Register.R11W: value = (ushort)c.R11; return true;
            case Register.R12W: value = (ushort)c.R12; return true;
            case Register.R13W: value = (ushort)c.R13; return true;
            case Register.R14W: value = (ushort)c.R14; return true;
            case Register.R15W: value = (ushort)c.R15; return true;

            case Register.AL: value = (byte)c.Rax; return true;
            case Register.AH: value = (byte)(c.Rax >> 8); return true;
            case Register.CL: value = (byte)c.Rcx; return true;
            case Register.CH: value = (byte)(c.Rcx >> 8); return true;
            case Register.DL: value = (byte)c.Rdx; return true;
            case Register.DH: value = (byte)(c.Rdx >> 8); return true;
            case Register.BL: value = (byte)c.Rbx; return true;
            case Register.BH: value = (byte)(c.Rbx >> 8); return true;
            case Register.SPL: value = (byte)c.Rsp; return true;
            case Register.BPL: value = (byte)c.Rbp; return true;
            case Register.SIL: value = (byte)c.Rsi; return true;
            case Register.DIL: value = (byte)c.Rdi; return true;
            case Register.R8L: value = (byte)c.R8; return true;
            case Register.R9L: value = (byte)c.R9; return true;
            case Register.R10L: value = (byte)c.R10; return true;
            case Register.R11L: value = (byte)c.R11; return true;
            case Register.R12L: value = (byte)c.R12; return true;
            case Register.R13L: value = (byte)c.R13; return true;
            case Register.R14L: value = (byte)c.R14; return true;
            case Register.R15L: value = (byte)c.R15; return true;

            default:
                value = 0;
                return false;
        }
    }
}
