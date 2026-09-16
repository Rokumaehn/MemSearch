using Iced.Intel;

namespace MemSearch;

internal sealed record DisassembledInstruction(ulong Address, byte[] Bytes, string Text, Instruction Instruction)
{
    public int Length => Bytes.Length;
    public ulong NextAddress => Address + (ulong)Bytes.Length;
}

internal sealed class DisassemblyService
{
    private readonly int _bitness;

    public DisassemblyService(int bitness) => _bitness = bitness;

    public List<DisassembledInstruction> Decode(byte[] code, ulong address, int maxInstructions)
    {
        var result = new List<DisassembledInstruction>();
        var reader = new ByteArrayCodeReader(code);
        var decoder = Decoder.Create(_bitness, reader);
        decoder.IP = address;

        var formatter = new MasmFormatter();
        formatter.Options.RipRelativeAddresses = true;
        var output = new StringOutput();

        int index = 0;
        while (index < code.Length && result.Count < maxInstructions)
        {
            Instruction instruction = decoder.Decode();
            int length = instruction.Length;
            if (length <= 0)
                break;

            int available = Math.Min(length, code.Length - index);
            var bytes = new byte[available];
            Array.Copy(code, index, bytes, 0, available);

            formatter.Format(instruction, output);
            result.Add(new DisassembledInstruction(instruction.IP, bytes, output.ToStringAndReset(), instruction));

            index += length;
        }

        return result;
    }

    public List<DisassembledInstruction> DecodeForward(ProcessMemory memory, ulong address, int maxInstructions, int maxBytes = 4096)
    {
        byte[]? code = memory.ReadBytes(address, maxBytes);
        return code is null ? new List<DisassembledInstruction>() : Decode(code, address, maxInstructions);
    }

    /// <summary>
    /// Heuristically decodes instructions that end exactly at <paramref name="address"/>,
    /// by trying every byte boundary in a window before it.
    /// </summary>
    public List<DisassembledInstruction> DecodeBackward(ProcessMemory memory, ulong address, int maxInstructions, int window = 256)
    {
        ulong start = address > (ulong)window ? address - (ulong)window : 0;
        int size = (int)(address - start);
        if (size <= 0)
            return new List<DisassembledInstruction>();

        byte[]? code = memory.ReadBytes(start, size);
        if (code is null)
            return new List<DisassembledInstruction>();

        for (int offset = 0; offset < code.Length; offset++)
        {
            byte[] slice = code[offset..];
            List<DisassembledInstruction> chain = Decode(slice, start + (ulong)offset, 64);
            if (chain.Count == 0)
                continue;

            if (chain[^1].NextAddress == address)
            {
                int take = Math.Min(maxInstructions, chain.Count);
                return chain.GetRange(chain.Count - take, take);
            }
        }

        return new List<DisassembledInstruction>();
    }

    /// <summary>
    /// Returns every single-instruction decode in front of <paramref name="address"/>
    /// that ends exactly at it. Used to locate the instruction a data breakpoint
    /// fault points past.
    /// </summary>
    public List<DisassembledInstruction> DecodeEndingAt(ProcessMemory memory, ulong address, int maxWindow = 15)
    {
        var result = new List<DisassembledInstruction>();
        ulong start = address > (ulong)maxWindow ? address - (ulong)maxWindow : 0;
        int size = (int)(address - start);
        if (size <= 0)
            return result;

        byte[]? code = memory.ReadBytes(start, size);
        if (code is null)
            return result;

        for (int offset = 0; offset < code.Length; offset++)
        {
            List<DisassembledInstruction> list = Decode(code[offset..], start + (ulong)offset, 1);
            if (list.Count > 0 && !list[0].Instruction.IsInvalid && list[0].NextAddress == address)
                result.Add(list[0]);
        }

        return result;
    }

    public static bool TryGetBranchTarget(in Instruction instruction, out ulong target)
    {
        switch (instruction.FlowControl)
        {
            case FlowControl.ConditionalBranch:
            case FlowControl.UnconditionalBranch:
            case FlowControl.Call:
                target = instruction.NearBranchTarget;
                return true;
            default:
                target = 0;
                return false;
        }
    }
}
