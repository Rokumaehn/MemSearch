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
    public bool Is64BitProcess { get; }

    private ProcessMemory(IntPtr handle, int processId, string processName, bool is64Bit)
    {
        Handle = handle;
        ProcessId = processId;
        ProcessName = processName;
        Is64BitProcess = is64Bit;
    }

    public static ProcessMemory Open(int processId, string processName)
    {
        IntPtr handle = NativeMethods.OpenProcess(Access, false, processId);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to open process {processName} (PID {processId}).");

        bool is64Bit = true;
        if (NativeMethods.IsWow64Process(handle, out bool wow64))
            is64Bit = !wow64;

        return new ProcessMemory(handle, processId, processName, is64Bit);
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

    public byte[]? ReadBytes(ulong address, int count)
    {
        var buffer = new byte[count];
        if (ReadBytes(address, buffer, count, out int read) && read == count)
            return buffer;
        return null;
    }

    /// <summary>
    /// Writes to memory that may be read-only or executable by temporarily
    /// granting write access and flushing the instruction cache afterwards.
    /// </summary>
    public bool WriteCode(ulong address, byte[] data)
    {
        if (data.Length == 0)
            return true;

        var addressPtr = unchecked((IntPtr)(long)address);
        var size = (IntPtr)data.Length;

        bool changed = NativeMethods.VirtualProtectEx(
            Handle, addressPtr, size, NativeMethods.PAGE_EXECUTE_READWRITE, out uint oldProtect);

        bool ok = WriteBytes(address, data);

        if (changed)
            NativeMethods.VirtualProtectEx(Handle, addressPtr, size, oldProtect, out _);

        if (ok)
            NativeMethods.FlushInstructionCache(Handle, addressPtr, size);

        return ok;
    }

    /// <summary>
    /// Allocates executable memory as close as possible to <paramref name="nearAddress"/>
    /// so that rel32 jumps and RIP-relative operands stay reachable.
    /// </summary>
    public ulong? AllocateNear(ulong nearAddress, nuint size)
    {
        NativeMethods.GetSystemInfo(out var info);
        ulong granularity = info.dwAllocationGranularity == 0 ? 0x10000 : info.dwAllocationGranularity;
        const ulong maxDistance = 0x70000000;

        ulong aligned = nearAddress & ~(granularity - 1);

        for (ulong delta = 0; delta < maxDistance; delta += granularity)
        {
            ulong up = aligned + delta;
            if (TryAllocate(up, size, out ulong allocated))
                return allocated;

            if (delta != 0 && aligned >= delta)
            {
                ulong down = aligned - delta;
                if (TryAllocate(down, size, out allocated))
                    return allocated;
            }
        }

        return null;
    }

    private bool TryAllocate(ulong address, nuint size, out ulong allocated)
    {
        IntPtr result = NativeMethods.VirtualAllocEx(
            Handle,
            unchecked((IntPtr)(long)address),
            (IntPtr)size,
            NativeMethods.MEM_RESERVE | NativeMethods.MEM_COMMIT,
            NativeMethods.PAGE_EXECUTE_READWRITE);

        allocated = result == IntPtr.Zero ? 0 : unchecked((ulong)result.ToInt64());
        return result != IntPtr.Zero;
    }

    public void FreeMemory(ulong address)
    {
        if (address != 0)
            NativeMethods.VirtualFreeEx(Handle, unchecked((IntPtr)(long)address), IntPtr.Zero, NativeMethods.MEM_RELEASE);
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
