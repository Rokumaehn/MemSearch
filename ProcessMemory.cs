using System.ComponentModel;
using System.Runtime.InteropServices;

namespace MemSearch;

internal readonly record struct MemoryRegion(ulong Base, ulong Size);

internal sealed class ProcessMemory : IDisposable
{
    private const uint Access =
        NativeMethods.PROCESS_QUERY_INFORMATION |
        NativeMethods.PROCESS_VM_READ |
        NativeMethods.PROCESS_VM_WRITE |
        NativeMethods.PROCESS_VM_OPERATION;

    private bool _disposed;

    public IntPtr Handle { get; }
    public int ProcessId { get; }
    public string ProcessName { get; }

    private ProcessMemory(IntPtr handle, int processId, string processName)
    {
        Handle = handle;
        ProcessId = processId;
        ProcessName = processName;
    }

    public static ProcessMemory Open(int processId, string processName)
    {
        IntPtr handle = NativeMethods.OpenProcess(Access, false, processId);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to open process {processName} (PID {processId}).");

        return new ProcessMemory(handle, processId, processName);
    }

    /// <summary>
    /// Enumerates only committed, readable memory regions of the process,
    /// skipping free space, PAGE_NOACCESS and PAGE_GUARD pages.
    /// </summary>
    public List<MemoryRegion> EnumerateRegions()
    {
        var regions = new List<MemoryRegion>();
        ulong address = 0;
        const ulong MaxUserAddress = 0x0000_7FFF_FFFF_FFFF;
        int size = Marshal.SizeOf<NativeMethods.MEMORY_BASIC_INFORMATION>();

        while (address < MaxUserAddress)
        {
            IntPtr result = NativeMethods.VirtualQueryEx(Handle, unchecked((IntPtr)(long)address), out var mbi, (IntPtr)size);
            if (result == IntPtr.Zero)
                break;

            ulong baseAddress = unchecked((ulong)mbi.BaseAddress.ToInt64());
            ulong regionSize = unchecked((ulong)mbi.RegionSize.ToInt64());
            if (regionSize == 0)
                break;

            if (mbi.State == NativeMethods.MEM_COMMIT && IsReadable(mbi.Protect))
                regions.Add(new MemoryRegion(baseAddress, regionSize));

            ulong next = baseAddress + regionSize;
            if (next <= address)
                break;
            address = next;
        }

        return regions;
    }

    private static bool IsReadable(uint protect)
    {
        if ((protect & NativeMethods.PAGE_GUARD) != 0)
            return false;

        uint baseProtect = protect & 0xFF;
        return baseProtect != 0 && baseProtect != NativeMethods.PAGE_NOACCESS;
    }

    public bool ReadBytes(ulong address, byte[] buffer, int count, out int bytesRead)
    {
        bytesRead = 0;
        if (count <= 0)
            return true;

        bool ok = NativeMethods.ReadProcessMemory(
            Handle,
            unchecked((IntPtr)(long)address),
            buffer,
            (IntPtr)count,
            out IntPtr read);

        bytesRead = unchecked((int)read.ToInt64());
        return ok && bytesRead == count;
    }

    public bool WriteBytes(ulong address, byte[] data)
    {
        if (data.Length == 0)
            return true;

        bool ok = NativeMethods.WriteProcessMemory(
            Handle,
            unchecked((IntPtr)(long)address),
            data,
            (IntPtr)data.Length,
            out IntPtr written);

        return ok && written.ToInt64() == data.Length;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        if (Handle != IntPtr.Zero)
            NativeMethods.CloseHandle(Handle);
    }
}
