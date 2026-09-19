using System.Runtime.InteropServices;

namespace OmniHax;

internal static partial class NativeMethods
{
    // ---- Debugger constants ----
    public const uint DBG_CONTINUE = 0x00010002;
    public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    public const uint EXCEPTION_BREAKPOINT = 0x80000003;
    public const uint STATUS_ACCESS_VIOLATION = 0xC0000005;
    public const uint STATUS_GUARD_PAGE_VIOLATION = 0x80000001;

    public const uint EXCEPTION_DEBUG_EVENT = 1;
    public const uint CREATE_THREAD_DEBUG_EVENT = 2;
    public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    public const uint EXIT_THREAD_DEBUG_EVENT = 4;
    public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    public const uint LOAD_DLL_DEBUG_EVENT = 6;
    public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    public const uint OUTPUT_DEBUG_STRING_EVENT = 8;
    public const uint RIP_EVENT = 9;

    // ---- Thread access rights ----
    public const uint THREAD_SUSPEND_RESUME = 0x0002;
    public const uint THREAD_GET_CONTEXT = 0x0008;
    public const uint THREAD_SET_CONTEXT = 0x0010;
    public const uint THREAD_QUERY_INFORMATION = 0x0040;
    public const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;

    // Thread information class used to query/set debugger hiding.
    public const int ThreadHideFromDebugger = 17;

    public const uint CONTEXT_DEBUG_REGISTERS = 0x00100010;
    public const uint CONTEXT_CONTROL = 0x00100001;
    public const uint CONTEXT_INTEGER = 0x00100002;

    // ---- Memory allocation / protection ----
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_READWRITE = 0x04;

    public const uint TH32CS_SNAPTHREAD = 0x00000004;

    // Token / privilege constants.
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint SE_PRIVILEGE_ENABLED = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_RECORD
    {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public IntPtr ExceptionRecordPtr;
        public IntPtr ExceptionAddress;
        public uint NumberParameters;
        public uint Unused;
        public long ExceptionInformation0;
        public long ExceptionInformation1;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_DEBUG_INFO
    {
        public EXCEPTION_RECORD ExceptionRecord;
        public uint FirstChance;
    }

    [StructLayout(LayoutKind.Explicit, Size = 176)]
    public struct DEBUG_EVENT
    {
        [FieldOffset(0)] public uint DebugEventCode;
        [FieldOffset(4)] public uint ProcessId;
        [FieldOffset(8)] public uint ThreadId;
        [FieldOffset(16)] public EXCEPTION_DEBUG_INFO Exception;

        // Native EXCEPTION_DEBUG_INFO.dwFirstChance sits after the full 152-byte
        // EXCEPTION_RECORD, so read it at its true offset.
        [FieldOffset(168)] public uint ExceptionFirstChance;
    }

    // x64 CONTEXT laid out explicitly; only the fields we need are exposed.
    [StructLayout(LayoutKind.Explicit, Size = 1232)]
    public struct CONTEXT64
    {
        [FieldOffset(0x30)] public uint ContextFlags;
        [FieldOffset(0x44)] public uint EFlags;
        [FieldOffset(0x48)] public ulong Dr0;
        [FieldOffset(0x50)] public ulong Dr1;
        [FieldOffset(0x58)] public ulong Dr2;
        [FieldOffset(0x60)] public ulong Dr3;
        [FieldOffset(0x68)] public ulong Dr6;
        [FieldOffset(0x70)] public ulong Dr7;
        [FieldOffset(0x78)] public ulong Rax;
        [FieldOffset(0x80)] public ulong Rcx;
        [FieldOffset(0x88)] public ulong Rdx;
        [FieldOffset(0x90)] public ulong Rbx;
        [FieldOffset(0x98)] public ulong Rsp;
        [FieldOffset(0xA0)] public ulong Rbp;
        [FieldOffset(0xA8)] public ulong Rsi;
        [FieldOffset(0xB0)] public ulong Rdi;
        [FieldOffset(0xB8)] public ulong R8;
        [FieldOffset(0xC0)] public ulong R9;
        [FieldOffset(0xC8)] public ulong R10;
        [FieldOffset(0xD0)] public ulong R11;
        [FieldOffset(0xD8)] public ulong R12;
        [FieldOffset(0xE0)] public ulong R13;
        [FieldOffset(0xE8)] public ulong R14;
        [FieldOffset(0xF0)] public ulong R15;
        [FieldOffset(0xF8)] public ulong Rip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DebugActiveProcess(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DebugActiveProcessStop(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DebugSetProcessKillOnExit([MarshalAs(UnmanagedType.Bool)] bool killOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(
        IntPtr threadHandle,
        int threadInformationClass,
        IntPtr threadInformation,
        int threadInformationLength,
        IntPtr returnLength);

    /// <summary>
    /// Queries the thread's ThreadHideFromDebugger flag. The buffer must be a single
    /// byte (BOOLEAN); using a 4-byte size returns STATUS_INVALID_PARAMETER_4.
    /// </summary>
    public static bool TryQueryThreadHidden(IntPtr threadHandle, out bool hidden)
    {
        hidden = false;
        IntPtr buffer = Marshal.AllocHGlobal(1);

        try
        {
            Marshal.WriteByte(buffer, 0, 0);
            int status = NtQueryInformationThread(threadHandle, ThreadHideFromDebugger, buffer, 1, IntPtr.Zero);
            if (status != 0)
                return false;

            hidden = Marshal.ReadByte(buffer) != 0;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr dwSize);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);
}
