namespace MemSearch;

internal readonly record struct DebugRegisters(ulong Dr0, ulong Dr1, ulong Dr2, ulong Dr3, ulong Dr7);

internal enum ProbeMode
{
    Normal,
    AttachOnly,
    ExternalDr,
    ExternalGuard,
    DecoyBaseline,
    DecoyGuard,
    DecoyDr
}

internal enum DecoyKind
{
    Baseline,
    Guard,
    Dr
}

internal enum AccessMechanism
{
    /// <summary>Hardware debug registers (detected by some anti-debug targets).</summary>
    HardwareBreakpoints,

    /// <summary>PAGE_GUARD on the watched page, handled by the debugger (no debug registers).</summary>
    GuardPage,

    /// <summary>Hardware breakpoint handled by an injected in-process VEH (no debugger).</summary>
    InProcessVeh
}

internal sealed record MechanismOption(AccessMechanism Type, string Name);

/// <summary>
/// Common surface shared by the debugger-based tracker and the external-DR probe.
/// </summary>
internal interface IAccessTracker : IDisposable
{
    bool IsRunning { get; }
    ulong WatchedAddress { get; }
    int WatchedSize { get; }
    bool IsAligned { get; }
    IReadOnlyCollection<AccessHit> GetHits();
    IReadOnlyList<string> DrainLog();
    void ClearHits();
    void Start();
    void Stop();
}
