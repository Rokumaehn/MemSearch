using Iced.Intel;

namespace MemSearch;

/// <summary>
/// Shared helpers for resolving a memory operand's effective address from a
/// captured thread context, and for matching it against a watched range.
/// </summary>
internal static class RegisterAddress
{
    public static bool TryCompute(in UsedMemory memory, in NativeMethods.CONTEXT64 context, out ulong address)
    {
        address = memory.Displacement;

        Register @base = memory.Base;
        if (@base != Register.None)
        {
            if (!TryGetRegisterValue(@base, in context, out ulong value))
            {
                address = 0;
                return false;
            }
            address += value;
        }

        Register index = memory.Index;
        if (index != Register.None)
        {
            if (!TryGetRegisterValue(index, in context, out ulong value))
            {
                address = 0;
                return false;
            }
            address += value * (ulong)(uint)memory.Scale;
        }

        switch (memory.AddressSize)
        {
            case CodeSize.Code16:
                address = (ushort)address;
                break;
            case CodeSize.Code32:
                address = (uint)address;
                break;
        }

        return true;
    }

    public static bool Overlaps(ulong address, in UsedMemory memory, ulong watchAddress, int watchSize)
    {
        ulong accessSize = (ulong)Math.Max(1, memory.MemorySize.GetSize());
        ulong accessEnd = address + accessSize;
        ulong watchEnd = watchAddress + (ulong)Math.Max(1, watchSize);
        return address < watchEnd && watchAddress < accessEnd;
    }

    public static bool IsWrite(OpAccess access) =>
        access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite;

    public static bool IsRead(OpAccess access) =>
        access is OpAccess.Read or OpAccess.CondRead or OpAccess.ReadWrite or OpAccess.ReadCondWrite;

    public static bool TryGetRegisterValue(Register register, in NativeMethods.CONTEXT64 c, out ulong value)
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
