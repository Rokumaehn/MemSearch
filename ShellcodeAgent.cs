using System.IO;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace OmniHax;

/// <summary>
/// Builds the x86-64 shellcode injected into the target:
/// a VEH registration stub, a teardown stub, a VEH handler that records
/// STATUS_SINGLE_STEP hits (from DR0) plus the faulting thread's GPRs into a ring
/// buffer, and a data block with resolved pointers.
/// </summary>
internal static class ShellcodeAgent
{
    public const int Capacity = 1 << 14;
    public const int EntrySize = 0x90;
    public const int CodeSize = 0x1000;
    public const int HandlerOffset = 0x000;
    public const int StubOffset = 0x200;
    public const int TeardownStubOffset = 0x240;
    public const int DataOffset = 0x300;
    public const int AddVehPtrOffset = DataOffset + 0x00;
    public const int GetTidPtrOffset = DataOffset + 0x08;
    public const int WriteIndexOffset = DataOffset + 0x10;
    public const int EntriesPtrOffset = DataOffset + 0x18;
    public const int RemoveVehPtrOffset = DataOffset + 0x20;
    public const int VehHandleOffset = DataOffset + 0x28;

    private const uint StatusSingleStep = 0x80000004;

    public static byte[] Build(ulong codeBase, ulong addVehPtr, ulong getTidPtr, ulong removeVehPtr, ulong entriesBase)
    {
        byte[] handler = AssembleHandler(codeBase);
        if (handler.Length > StubOffset)
            throw new InvalidOperationException($"Handler shellcode too large ({handler.Length} bytes).");

        byte[] stub = AssembleStub(codeBase);
        if (StubOffset + stub.Length > TeardownStubOffset)
            throw new InvalidOperationException($"Stub shellcode too large ({stub.Length} bytes).");

        byte[] teardown = AssembleTeardownStub(codeBase);
        if (TeardownStubOffset + teardown.Length > DataOffset)
            throw new InvalidOperationException($"Teardown shellcode too large ({teardown.Length} bytes).");

        var blob = new byte[CodeSize];
        Array.Copy(handler, 0, blob, HandlerOffset, handler.Length);
        Array.Copy(stub, 0, blob, StubOffset, stub.Length);
        Array.Copy(teardown, 0, blob, TeardownStubOffset, teardown.Length);

        WriteUInt64(blob, AddVehPtrOffset, addVehPtr);
        WriteUInt64(blob, GetTidPtrOffset, getTidPtr);
        WriteUInt64(blob, WriteIndexOffset, 0);
        WriteUInt64(blob, EntriesPtrOffset, entriesBase);
        WriteUInt64(blob, RemoveVehPtrOffset, removeVehPtr);
        WriteUInt64(blob, VehHandleOffset, 0);

        return blob;
    }

    // Context offsets (x64 CONTEXT).
    private const int CtxDr6 = 0x68;
    private const int CtxRip = 0xF8;
    private const int CtxRax = 0x78;

    // Entry offsets for the captured GPRs (entry+16, in context order).
    private const int EntryRegs = 16;
    private const int EntryStride = 8;

    private static byte[] AssembleHandler(ulong codeBase)
    {
        var c = new Assembler(64);
        var passSearch = c.CreateLabel();
        var done = c.CreateLabel();

        // RCX = PEXCEPTION_POINTERS
        c.mov(rdx, __qword_ptr[rcx]);            // ExceptionRecord
        c.mov(eax, __dword_ptr[rdx]);            // ExceptionCode
        c.cmp(eax, StatusSingleStep);
        c.jne(passSearch);

        c.mov(r8, __qword_ptr[rcx + 8]);         // ContextRecord
        c.mov(rax, __qword_ptr[r8 + CtxDr6]);    // Dr6
        c.test(al, 1);
        c.jz(passSearch);

        c.mov(rbx, __qword_ptr[rdx + 0x10]);     // ExceptionAddress (rip)

        // tid = GetCurrentThreadId(); shadow space + alignment.
        c.mov(rax, codeBase + GetTidPtrOffset);
        c.mov(rax, __qword_ptr[rax]);
        c.sub(rsp, 0x28);
        c.call(rax);
        c.add(rsp, 0x28);
        c.mov(r9d, eax);

        // index = lock xadd [writeIndex], 1; slot = index & (Capacity-1)
        c.mov(r11, codeBase + WriteIndexOffset);
        c.mov(rax, 1);
        c.@lock.xadd(__qword_ptr[r11], rax);
        c.and(rax, Capacity - 1);
        c.imul(rax, rax, EntrySize);

        c.mov(rdx, codeBase + EntriesPtrOffset);
        c.mov(rdx, __qword_ptr[rdx]);
        c.add(rdx, rax);

        c.mov(__qword_ptr[rdx], rbx);            // entry.rip
        c.mov(__dword_ptr[rdx + 8], r9d);        // entry.tid

        // Copy 16 GPRs from the context (r8) into the entry.
        for (int i = 0; i < 16; i++)
        {
            c.mov(rax, __qword_ptr[r8 + CtxRax + i * EntryStride]);
            c.mov(__qword_ptr[rdx + EntryRegs + i * EntryStride], rax);
        }

        c.Label(ref done);
        c.mov(eax, -1);                          // EXCEPTION_CONTINUE_EXECUTION
        c.ret();

        c.Label(ref passSearch);
        c.xor(eax, eax);                         // EXCEPTION_CONTINUE_SEARCH
        c.ret();

        return Assemble(c, codeBase);
    }

    private static byte[] AssembleStub(ulong codeBase)
    {
        var c = new Assembler(64);
        c.mov(rcx, 1);                           // First = 1
        c.mov(rdx, codeBase);                    // handler address
        c.mov(rax, codeBase + AddVehPtrOffset);
        c.mov(rax, __qword_ptr[rax]);
        c.sub(rsp, 0x28);                        // shadow space + alignment
        c.call(rax);
        c.add(rsp, 0x28);

        c.mov(rcx, codeBase + VehHandleOffset);  // store the returned handle
        c.mov(__qword_ptr[rcx], rax);
        c.ret();

        return Assemble(c, codeBase + StubOffset);
    }

    private static byte[] AssembleTeardownStub(ulong codeBase)
    {
        var c = new Assembler(64);
        c.mov(rcx, codeBase + VehHandleOffset);
        c.mov(rcx, __qword_ptr[rcx]);
        c.mov(rax, codeBase + RemoveVehPtrOffset);
        c.mov(rax, __qword_ptr[rax]);
        c.sub(rsp, 0x28);
        c.call(rax);
        c.add(rsp, 0x28);
        c.ret();

        return Assemble(c, codeBase + TeardownStubOffset);
    }

    private static byte[] Assemble(Assembler assembler, ulong rip)
    {
        using var stream = new MemoryStream();
        assembler.Assemble(new StreamCodeWriter(stream), rip);
        return stream.ToArray();
    }

    private static void WriteUInt64(byte[] buffer, int offset, ulong value)
    {
        for (int i = 0; i < 8; i++)
            buffer[offset + i] = (byte)(value >> (8 * i));
    }
}
