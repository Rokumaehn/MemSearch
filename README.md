# Omni Hax

A Windows x64 memory scanner, editor, and "what accesses this address" tool.

![Architecture](docs/architecture.svg)

It can locate values in another process's virtual memory, narrow the results with
successive scans, edit the values in place, browse/disassemble the target's code,
edit that assembly, and observe which instructions read/write/execute a given
address.

> For local debugging, reverse engineering, and single-player/offline use. Running a
> debugger or injecting code into a process may be detected by anti-cheat and is
> your responsibility.

## Features

- Open a running process (optionally only those with visible windows).
- Scan **only committed, readable memory regions** for values of a selected datatype.
- Datatypes: `Byte`, `SByte`, `Word`, `Int16`, `DWord`, `Int32`, `QWord`, `Int64`,
  `Float`, `Double` (little-endian).
- Successive searches narrow the candidate addresses; at ≤ 100 candidates the results
  are shown in an editable list (editing writes to the target).
- **Access tracking** ("find out what writes/accesses/executes this address") with
  three selectable mechanisms.
- **Code browser** with disassembly (Iced), navigation/follow, and in-place assembly
  editing (shorter edits are NOP-padded; longer edits are moved to a code cave with a
  jump trampoline).
- Diagnostics pane and a set of probes for troubleshooting.

## Requirements

- Windows 10/11 x64.
- .NET SDK 10 (`net10.0-windows`).
- Administrator rights (the app manifest requests elevation; needed to open/write
  other processes).
- NuGet package `Iced` 1.21.0 (restored automatically).

## Build & run

```powershell
dotnet build
# run (will prompt for elevation because of app.manifest)
.\bin\Debug\net10.0-windows\OmniHax.exe
```

If the environment blocks the unsigned apphost, run via the SDK host instead:

```powershell
dotnet .\bin\Debug\net10.0-windows\OmniHax.dll
```

### Smart App Control / WDAC

On machines with **Smart App Control** (or WDAC application control) enforced,
unsigned locally-built binaries are blocked with
`0x800711C7 "Application Control policy has blocked this file"` — even through the
`dotnet` host. There is no per-app override; such a machine cannot run this app until
the policy is turned off. Use an unmanaged machine/VM if you cannot change it.

## Usage

### Scanning

1. **Open Process…** → pick a process (tick "Only processes with visible windows" to
   filter).
2. Choose a **Type**, enter a **Value**, press **Search** (or Enter). Optionally tick
   **Writable only** to scan just writable regions and **Size-aligned** to only match
   addresses aligned to the datatype size.
3. Change the value in the target and search again to narrow the candidate set.
4. When ≤ 100 candidates remain they are listed; edit a **Value** cell to write it to
   the target. **Reset Search** clears the state and re-enables the type control.

### Unknown-value search

If you don't know the value yet, leave the **Value** box empty and press **Search**:
this snapshots every candidate in the process instead of matching a pattern. Then
change the value in the target and press:

- **`<`** keep addresses whose value decreased,
- **`>`** keep addresses whose value increased,
- **`=`** keep addresses whose value is unchanged.

Each press compares against the previous snapshot and updates it, so repeated presses
narrow the list. Because it records every address, an unknown scan uses a lot of
memory — the **Writable only** and **Size-aligned** options (which also apply to direct
searches) reduce it. Direct and unknown searches are mutually exclusive: once one has
started, the other's controls stay locked until **Reset Search**.

### Access tracking

Right-click an address in the results list. Pick a mechanism under
**Options → Access type**:

| Mechanism | How it works | When to use |
|---|---|---|
| **Hardware breakpoints (debugger)** | Attaches as a debugger and programs a `DR0` watch. | Default; fastest and most precise on normal targets. |
| **Page-guard (debugger)** | `PAGE_GUARD` on the watched page, handled by the debugger. Watches reads/writes, and execution (one-shot). | When debug registers are detected, but you still trust the debug port. Slower (page-granular). |
| **In-process VEH (no debugger)** | Injects a small VEH agent and arms `DR0`; no debugger is attached. | Targets that hide threads from debuggers (`ThreadHideFromDebugger`) or otherwise resist the debug port. |

Then choose **Find out what writes / accesses / executes this address**. Hits appear
in a list; double-click a hit to open it in the code browser.

> Background: `ThreadHideFromDebugger` stops a thread's exceptions from reaching a
> debugger, so debugger-based hardware/guard breakpoints silently miss (and can crash)
> such targets. A Vectored Exception Handler runs in-process and **is** still invoked,
> which is why the injected mechanism exists. It requires code injection
> (`VirtualAllocEx` + `CreateRemoteThread`), which is itself detectable.

The tracker list can **auto-stop** after a given number of distinct writers (set the
number in the bottom row).

### Codes (freeze list / scripts)

The lower half of the window is tabbed: **Results** holds the search hits, **Codes**
holds persistent entries that are re-applied while enabled.

- Right-click a result → **Register** adds a data entry (`Enabled`, `Description`,
  `Datatype`, `Address`, `Value`).
- Right-click an instruction in an access-tracking window → **Register** adds a
  **Script** entry whose default is that instruction.
- Tick **Enabled** on a data entry to overwrite the address with the value every
  *Freeze interval* (editable, default 500 ms).
- A **Script** entry's `Value` always shows `<asm>`; double-click it (or right-click →
  *Edit script...*) to edit the assembly. Enabling injects it exactly like the code
  browser (in place with NOP padding, or a code cave + jump trampoline); disabling
  writes the original bytes back and frees the cave.
- Only one entry may be active per address.
- **Remove** (button, right-click, or Delete) drops an entry and restores an applied
  script. Closing the app leaves applied scripts in place.

### Code browser

Open it from **Windows → Code browser** (or right-click an address → *Browse memory
here*). It opens at the selected result or the target's main module base; use the
**Go** box to jump to any hex/decimal address.

- Shows address, raw bytes, and disassembly (Masm syntax).
- **Go** to an address, **Back**, **Follow** a branch/call, **Refresh**.
- Edit the *Instruction* cell to change the assembly at that address:
  - assemblies that fit in the original length are written in place (NOP-padded),
  - longer edits are relocated to an allocated code cave with a jump trampoline.
- The assembler is a limited Intel-syntax parser (registers, immediates, memory
  operands with size hints, `lock`, direct branches); unsupported syntax reports an
  error.

### Diagnostics

Every tracking window has a **Diagnostics** expander (Copy / Save). The **Diagnostics**
menu has probes used during development:
attach-only, external hardware breakpoint (no debugger), external page-guard, and
three "decoy" probes (allocate/guard/DR an untouched page) to test whether a target
detects these techniques.

## Known limitations

- x64 targets only (32-bit/WOW64 is rejected).
- Hardware breakpoints: 4 slots; the tracker preserves/restores existing debug registers.
- The page-guard mechanism is page-granular and can slow a busy page. For execute watches it single-steps instructions on the page until the watched instruction runs (capped at 200,000 steps), then records the first execution and stops.
- The in-process VEH mechanism requires code injection; on a kernel anti-cheat it will
  be detected or blocked.
- The assembler supports a subset of instructions.

## Project layout

| File | Purpose |
|---|---|
| `MainWindow.xaml(.cs)` | Main UI, scanning, process open, results editing, context menu. |
| `ProcessPickerWindow.xaml(.cs)` | Process list with the visible-windows filter. |
| `ProcessMemory.cs` | Handle wrapper: regions, read/write, `AllocateNear`, `WriteCode`. |
| `MemoryScanner.cs` | First/narrow scans over committed regions. |
| `MemoryValueTypeInfo.cs` | Datatype metadata, parse/format/encode. |
| `ResultRow.cs` | Editable result row that writes back to memory. |
| `AccessTracking.cs` | `AccessKind`, `AccessHit`, mechanisms/probe enums, `IAccessTracker`. |
| `HardwareBreakpointTracker.cs` | Debugger-based DR/guard tracking + diagnostics. |
| `ExternalBreakpointProbe.cs`, `ExternalGuardProbe.cs`, `DecoyProbe.cs` | Diagnostic probes. |
| `InProcessBreakpointTracker.cs` | Injected-VEH tracking (no debugger). |
| `ShellcodeAgent.cs` | Iced-generated VEH agent shellcode. |
| `NativeMethods*.cs` | P/Invoke (kernel32/user32/ntdll/psapi/advapi32). |
| `DisassemblyService.cs`, `AssemblerService.cs` | Disassembly and assembling/code caves. |
| `CodeBrowserWindow.xaml(.cs)` | Disassembly browser + assembly editing. |
| `AccessTrackerWindow.xaml(.cs)` | Hits list, diagnostics pane, auto-stop. |
| `Privileges.cs` | Enables `SeDebugPrivilege`. |
