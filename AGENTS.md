# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`MemSearch` — a WPF (`net10.0-windows`) Windows x64 memory scanner/editor and
access-tracking tool. Admin rights are requested via `app.manifest`. The only NuGet
dependency is `Iced` (x86/x64 disassembler + assembler/encoder).

## Build & verify

```powershell
dotnet build
```

The build must be clean (0 warnings, 0 errors). There is no unit-test project; verify
logic with a temporary console harness that references the source files directly
(see "Testing" below) and by running the app.

If `dotnet build` fails with `MSB3027/MSB3026` (file locked), the app is running —
close `MemSearch.exe`. If the environment blocks the built binary
(`0x800711C7`, Smart App Control/WDAC), build to a temp output instead:

```powershell
dotnet build -o "$env:TEMP\memsearch-verify"
```

## Architecture notes

- All interop lives in `NativeMethods*.cs` (partial `NativeMethods`).
- `IAccessTracker` (in `AccessTracking.cs`) is implemented by
  `HardwareBreakpointTracker` (debugger-based), `InProcessBreakpointTracker`
  (injected in-process VEH, no debugger), and the diagnostic probes.
- `ShellcodeAgent.cs` builds the injected x86-64 agent with Iced. Conventions that
  matter: Windows x64 calls require **32 bytes of shadow space** and 16-byte stack
  alignment (`sub rsp, 0x28` / `add rsp, 0x28` around a call); data pointers are placed
  at fixed offsets (see the `*Offset` constants) and patched into the blob.
- The injected data-breakpoint handler sets/uses `DR0` and is registered with
  `AddVectoredExceptionHandler`; `Stop()` must remove the handler
  (`RemoveVectoredExceptionHandler`) and free its allocations.

## Conventions

- C# with nullable enabled. Match the surrounding style; avoid new dependencies.
- Do **not** add comments unless they explain non-obvious behaviour; keep XML docs terse.
- WPF windows use code-behind (no MVVM framework). The XAML-generated window classes
  are `public`, so constructors that take internal types must be `internal`.
- The app is elevated; opening other processes/threads is expected. Guard native calls
  and log failures via the tracker `Log(...)` queue (shown in the Diagnostics pane).

## Testing

There is no test project. For behavioural checks, create a temporary console project
(outside the repo) that `<Compile Include>`s the relevant source files plus `Iced`,
and run it with the SDK host (`dotnet bin\Release\net10.0\<name>.dll`). A useful target
is a small program that hides its writer thread with
`NtSetInformationThread(ThreadHideFromDebugger)` and then writes to a known address:
the debugger-based tracker misses it, the in-process VEH tracker must catch it.
