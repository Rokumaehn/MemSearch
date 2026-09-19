using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using Iced.Intel;

namespace MemSearch;

internal enum EditMode
{
    None,
    InPlace,
    CodeCave
}

internal sealed record EditResult(bool Success, EditMode Mode, string Message, ulong CaveAddress,
    ulong PatchAddress = 0, int PatchLength = 0, byte[]? OriginalBytes = null);

internal sealed class AssemblerService
{
    private const int MaxEncodedLength = 15;

    private readonly int _bitness;
    private readonly ProcessMemory _memory;
    private readonly DisassemblyService _disassembly;

    public AssemblerService(ProcessMemory memory, DisassemblyService disassembly, int bitness)
    {
        _memory = memory;
        _disassembly = disassembly;
        _bitness = bitness;
    }

    // ---------- Public API ----------

    public bool TryAssemble(string text, ulong address, out byte[] bytes, out string error)
    {
        bytes = Array.Empty<byte>();
        if (!TryParse(text, out ParsedInstruction? parsed, out error))
            return false;

        if (!TryBuild(parsed, address, out Instruction instruction, out error))
            return false;

        return TryEncode(new[] { instruction }, address, out bytes, out error);
    }

    public EditResult Apply(ulong address, string text)
    {
        if (!TryParse(text, out ParsedInstruction? parsed, out string error))
            return new EditResult(false, EditMode.None, error, 0);

        List<DisassembledInstruction> decoded = _disassembly.DecodeForward(_memory, address, 16, 64);
        if (decoded.Count == 0)
            return new EditResult(false, EditMode.None, "Could not read an instruction at this address.", 0);

        int originalLength = decoded[0].Length;

        if (TryBuild(parsed, address, out Instruction instruction, out _) &&
            TryEncode(new[] { instruction }, address, out byte[] inPlace, out _) &&
            inPlace.Length <= originalLength)
        {
            byte[] padded = PadWithNops(inPlace, originalLength);
            byte[]? original = _memory.ReadBytes(address, originalLength);
            if (!_memory.WriteCode(address, padded))
                return new EditResult(false, EditMode.None, "Failed to write to process memory.", 0);

            return new EditResult(true, EditMode.InPlace,
                $"Wrote {inPlace.Length} byte(s) in place ({originalLength - inPlace.Length} NOP filler).", 0,
                address, originalLength, original);
        }

        return BuildTrampoline(address, parsed, decoded, originalLength);
    }

    // ---------- Trampoline ----------

    private EditResult BuildTrampoline(ulong address, ParsedInstruction parsed, List<DisassembledInstruction> decoded, int originalLength)
    {
        const int jumpSize = 5; // rel32 jump

        int total = 0;
        var displaced = new List<DisassembledInstruction>();
        foreach (DisassembledInstruction d in decoded)
        {
            displaced.Add(d);
            total += d.Length;
            if (total >= jumpSize)
                break;
        }

        if (total < jumpSize)
            return new EditResult(false, EditMode.None, "Not enough instruction bytes available to build a trampoline.", 0);

        ulong backTarget = address + (ulong)total;
        int relocatedLength = total - displaced[0].Length;
        byte[]? original = _memory.ReadBytes(address, total);

        if (!TryBuild(parsed, 0, out Instruction userInstruction, out string buildError))
            return new EditResult(false, EditMode.None, buildError, 0);

        int userLength = Math.Min(TryLength(userInstruction), MaxEncodedLength);
        nuint caveSize = (nuint)(userLength + relocatedLength + jumpSize + 16);

        ulong? cave = _memory.AllocateNear(address, caveSize);
        if (cave is null)
            return new EditResult(false, EditMode.None, "Could not allocate executable memory near the target.", 0);

        ulong caveAddress = cave.Value;

        try
        {
            if (!TryBuild(parsed, caveAddress, out userInstruction, out buildError))
                throw new InvalidOperationException(buildError);

            var instructions = new List<Instruction> { userInstruction };
            for (int i = 1; i < displaced.Count; i++)
                instructions.Add(displaced[i].Instruction);
            instructions.Add(Instruction.CreateBranch(Code.Jmp_rel32_64, backTarget));

            if (!TryEncode(instructions, caveAddress, out byte[] caveBytes, out string caveError))
                throw new InvalidOperationException(caveError);

            // Patch the original location with a jump to the cave.
            var patchInstructions = new List<Instruction>
            {
                Instruction.CreateBranch(Code.Jmp_rel32_64, caveAddress)
            };

            if (!TryEncode(patchInstructions, address, out byte[] patchBytes, out string patchError))
                throw new InvalidOperationException(patchError);

            if (patchBytes.Length > total)
                throw new InvalidOperationException("Trampoline jump does not fit in the displaced bytes.");

            if (!_memory.WriteCode(caveAddress, caveBytes))
                throw new InvalidOperationException("Failed to write the code cave.");

            if (!_memory.WriteCode(address, PadWithNops(patchBytes, total)))
                throw new InvalidOperationException("Failed to patch the original code.");

            return new EditResult(true, EditMode.CodeCave,
                $"New code placed in a cave at 0x{caveAddress:X} with a jump trampoline.", caveAddress,
                address, total, original);
        }
        catch (Exception ex)
        {
            _memory.FreeMemory(caveAddress);
            return new EditResult(false, EditMode.None, ex.Message, 0);
        }
    }

    // ---------- Encoding ----------

    private bool TryEncode(IReadOnlyList<Instruction> instructions, ulong rip, out byte[] bytes, out string error)
    {
        var writer = new ByteCodeWriter();
        var block = new InstructionBlock(writer, instructions.ToList(), rip);

        if (!BlockEncoder.TryEncode(_bitness, block, out string? errorMessage, out _))
        {
            bytes = Array.Empty<byte>();
            error = string.IsNullOrEmpty(errorMessage) ? "Failed to encode instruction." : errorMessage;
            return false;
        }

        bytes = writer.ToArray();
        error = string.Empty;
        return true;
    }

    private int TryLength(Instruction instruction)
    {
        return TryEncode(new[] { instruction }, instruction.IP, out byte[] bytes, out _) ? bytes.Length : MaxEncodedLength;
    }

    // ---------- Build ----------

    private bool TryBuild(ParsedInstruction parsed, ulong rip, out Instruction instruction, out string error)
    {
        instruction = default;

        if (parsed.Branch && parsed.Operands.Length == 1 && parsed.Operands[0] is ImmOperand imm)
        {
            if (imm.Negative)
            {
                error = "Branch target cannot be negative.";
                return false;
            }

            foreach (Code code in GetBranchCodes(parsed.Mnemonic))
            {
                Instruction candidate = Instruction.CreateBranch(code, imm.Magnitude);
                if (parsed.Lock)
                    candidate.HasLockPrefix = true;

                if (TryEncode(new[] { candidate }, rip, out _, out _))
                {
                    instruction = candidate;
                    error = string.Empty;
                    return true;
                }
            }

            error = $"Branch target 0x{imm.Magnitude:X} is out of range.";
            return false;
        }

        if (!_codesByMnemonic.TryGetValue(parsed.Mnemonic, out List<Code>? candidates))
        {
            error = $"Unknown instruction '{parsed.Mnemonic}'.";
            return false;
        }

        int bestLength = int.MaxValue;

        foreach (Code code in candidates)
        {
            OpCodeInfo info = code.ToOpCode();
            if (info.OpCount != parsed.Operands.Length)
                continue;

            if (!Matches(info, parsed.Operands))
                continue;

            if (!TryCreate(code, parsed.Operands, parsed.Lock, out Instruction candidate))
                continue;

            if (!TryEncode(new[] { candidate }, rip, out byte[] encoded, out _))
                continue;

            int length = encoded.Length;
            if (length > MaxEncodedLength)
                continue;

            if (length < bestLength)
            {
                bestLength = length;
                instruction = candidate;
            }
        }

        if (bestLength == int.MaxValue)
        {
            error = "No valid encoding found for these operands.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool Matches(OpCodeInfo info, AsmOperand[] operands)
    {
        for (int i = 0; i < operands.Length; i++)
        {
            OpCodeOperandKind kind = info.GetOpKind(i);
            switch (operands[i])
            {
                case RegOperand reg:
                    if (!MatchesRegister(kind, reg))
                        return false;
                    break;

                case MemOperand mem:
                    if (!MatchesMemory(kind, mem))
                        return false;
                    break;

                case ImmOperand imm:
                    if (!MatchesImmediate(kind, imm))
                        return false;
                    break;
            }
        }

        return true;
    }

    private static bool MatchesRegister(OpCodeOperandKind kind, RegOperand reg) => kind switch
    {
        OpCodeOperandKind.r8_reg or OpCodeOperandKind.r8_opcode or OpCodeOperandKind.r8_or_mem => reg.Size == 8,
        OpCodeOperandKind.r16_reg or OpCodeOperandKind.r16_opcode or OpCodeOperandKind.r16_or_mem or OpCodeOperandKind.r16_reg_mem => reg.Size == 16,
        OpCodeOperandKind.r32_reg or OpCodeOperandKind.r32_opcode or OpCodeOperandKind.r32_or_mem or OpCodeOperandKind.r32_reg_mem => reg.Size == 32,
        OpCodeOperandKind.r64_reg or OpCodeOperandKind.r64_opcode or OpCodeOperandKind.r64_or_mem or OpCodeOperandKind.r64_reg_mem => reg.Size == 64,
        OpCodeOperandKind.al => reg.Register == Register.AL,
        OpCodeOperandKind.cl => reg.Register == Register.CL,
        OpCodeOperandKind.ax => reg.Register == Register.AX,
        OpCodeOperandKind.dx => reg.Register == Register.DX,
        OpCodeOperandKind.eax => reg.Register == Register.EAX,
        OpCodeOperandKind.rax => reg.Register == Register.RAX,
        _ => false
    };

    private static bool MatchesMemory(OpCodeOperandKind kind, MemOperand mem) => kind switch
    {
        OpCodeOperandKind.mem or OpCodeOperandKind.mem_offs => true,
        OpCodeOperandKind.r8_or_mem => mem.Size is null or 8,
        OpCodeOperandKind.r16_or_mem or OpCodeOperandKind.r16_reg_mem => mem.Size is null or 16,
        OpCodeOperandKind.r32_or_mem or OpCodeOperandKind.r32_reg_mem => mem.Size is null or 32,
        OpCodeOperandKind.r64_or_mem or OpCodeOperandKind.r64_reg_mem => mem.Size is null or 64,
        _ => false
    };

    private static bool MatchesImmediate(OpCodeOperandKind kind, ImmOperand imm) => kind switch
    {
        OpCodeOperandKind.imm8 => FitsSigned(imm, 8) || FitsUnsigned(imm, 8),
        OpCodeOperandKind.imm8sex16 or OpCodeOperandKind.imm8sex32 or OpCodeOperandKind.imm8sex64 => FitsSigned(imm, 8),
        OpCodeOperandKind.imm16 => FitsSigned(imm, 16) || FitsUnsigned(imm, 16),
        OpCodeOperandKind.imm32 => FitsSigned(imm, 32) || FitsUnsigned(imm, 32),
        OpCodeOperandKind.imm32sex64 => FitsSigned(imm, 32),
        OpCodeOperandKind.imm64 => FitsSigned(imm, 64) || FitsUnsigned(imm, 64),
        _ => false
    };

    private static bool TryCreate(Code code, AsmOperand[] ops, bool lockPrefix, out Instruction instruction)
    {
        instruction = default;

        try
        {
            switch (ops.Length)
            {
                case 0:
                    instruction = Instruction.Create(code);
                    break;

                case 1:
                    instruction = ops[0] switch
                    {
                        RegOperand r => Instruction.Create(code, r.Register),
                        MemOperand m => Instruction.Create(code, m.Memory),
                        ImmOperand i => CreateImmediate(code, i),
                        _ => default
                    };
                    break;

                case 2 when ops[0] is RegOperand a && ops[1] is RegOperand b:
                    instruction = Instruction.Create(code, a.Register, b.Register);
                    break;
                case 2 when ops[0] is RegOperand a && ops[1] is ImmOperand i:
                    instruction = Instruction.Create(code, a.Register, RawLong(i));
                    break;
                case 2 when ops[0] is RegOperand a && ops[1] is MemOperand m:
                    instruction = Instruction.Create(code, a.Register, m.Memory);
                    break;
                case 2 when ops[0] is MemOperand m && ops[1] is RegOperand b:
                    instruction = Instruction.Create(code, m.Memory, b.Register);
                    break;
                case 2 when ops[0] is MemOperand m && ops[1] is ImmOperand i:
                    if (!TryImm32(i, out int v32))
                        return false;
                    instruction = Instruction.Create(code, m.Memory, v32);
                    break;
                case 2 when ops[0] is ImmOperand i && ops[1] is RegOperand b:
                    if (!TryImm32(i, out int v32b))
                        return false;
                    instruction = Instruction.Create(code, v32b, b.Register);
                    break;

                case 3 when ops[0] is RegOperand a && ops[1] is RegOperand b && ops[2] is RegOperand c:
                    instruction = Instruction.Create(code, a.Register, b.Register, c.Register);
                    break;
                case 3 when ops[0] is RegOperand a && ops[1] is RegOperand b && ops[2] is ImmOperand i:
                    if (!TryImm32(i, out int v32c))
                        return false;
                    instruction = Instruction.Create(code, a.Register, b.Register, v32c);
                    break;
                case 3 when ops[0] is RegOperand a && ops[1] is RegOperand b && ops[2] is MemOperand m:
                    instruction = Instruction.Create(code, a.Register, b.Register, m.Memory);
                    break;
                case 3 when ops[0] is RegOperand a && ops[1] is MemOperand m && ops[2] is RegOperand c:
                    instruction = Instruction.Create(code, a.Register, m.Memory, c.Register);
                    break;
                case 3 when ops[0] is MemOperand m && ops[1] is RegOperand b && ops[2] is RegOperand c:
                    instruction = Instruction.Create(code, m.Memory, b.Register, c.Register);
                    break;

                case 4 when ops[0] is RegOperand a && ops[1] is RegOperand b && ops[2] is RegOperand c && ops[3] is RegOperand d:
                    instruction = Instruction.Create(code, a.Register, b.Register, c.Register, d.Register);
                    break;

                default:
                    return false;
            }
        }
        catch (Exception)
        {
            return false;
        }

        if (lockPrefix)
            instruction.HasLockPrefix = true;

        return true;
    }

    private static Instruction CreateImmediate(Code code, ImmOperand imm)
    {
        if (imm.Negative)
            return Instruction.Create(code, (int)RawLong(imm));
        return imm.Magnitude <= uint.MaxValue
            ? Instruction.Create(code, (uint)imm.Magnitude)
            : Instruction.Create(code, (int)RawLong(imm));
    }

    private static bool TryImm32(ImmOperand imm, out int value)
    {
        value = 0;
        if (imm.Negative)
        {
            if (imm.Magnitude > 0x80000000UL)
                return false;
            value = unchecked((int)(-(long)imm.Magnitude));
            return true;
        }

        if (imm.Magnitude > uint.MaxValue)
            return false;
        value = unchecked((int)imm.Magnitude);
        return true;
    }

    private static long RawLong(ImmOperand imm) =>
        imm.Negative ? unchecked(-(long)imm.Magnitude) : unchecked((long)imm.Magnitude);

    private static bool FitsUnsigned(ImmOperand imm, int bits) =>
        !imm.Negative && imm.Magnitude <= MaxUnsigned(bits);

    private static bool FitsSigned(ImmOperand imm, int bits)
    {
        if (bits >= 64)
            return imm.Negative ? imm.Magnitude <= 0x8000000000000000UL : imm.Magnitude <= long.MaxValue;

        ulong limit = 1UL << (bits - 1);
        return imm.Negative ? imm.Magnitude <= limit : imm.Magnitude < limit;
    }

    private static ulong MaxUnsigned(int bits) => bits >= 64 ? ulong.MaxValue : (1UL << bits) - 1;

    private static byte[] PadWithNops(byte[] data, int length)
    {
        if (data.Length >= length)
            return data;

        var result = new byte[length];
        Array.Copy(data, result, data.Length);
        for (int i = data.Length; i < length; i++)
            result[i] = 0x90;
        return result;
    }

    // ---------- Parsing ----------

    private bool TryParse(string text, [NotNullWhen(true)] out ParsedInstruction? parsed, out string error)
    {
        parsed = null;
        error = string.Empty;

        text = (text ?? string.Empty).Trim();
        int comment = text.IndexOf(';');
        if (comment >= 0)
            text = text[..comment];
        text = text.Trim();
        if (text.Length == 0)
        {
            error = "Enter an instruction.";
            return false;
        }

        bool lockPrefix = false;
        var words = text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        int start = 0;
        while (start < words.Length)
        {
            string w = words[start].ToLowerInvariant();
            if (w == "lock")
            {
                lockPrefix = true;
                start++;
            }
            else if (w is "rep" or "repe" or "repz" or "repne" or "repnz")
            {
                error = "String repeat prefixes are not supported.";
                return false;
            }
            else
            {
                break;
            }
        }

        string remainder = string.Join(' ', words[start..]);
        if (remainder.Length == 0)
        {
            error = "Enter an instruction.";
            return false;
        }

        int space = remainder.IndexOf(' ');
        string mnemonic = (space < 0 ? remainder : remainder[..space]).ToLowerInvariant();
        string operandText = space < 0 ? string.Empty : remainder[(space + 1)..].Trim();

        if (!_mnemonics.TryGetValue(mnemonic, out Mnemonic mnemonicValue))
        {
            error = $"Unknown instruction '{mnemonic}'.";
            return false;
        }

        string canonical = mnemonicValue.ToString().ToLowerInvariant();

        var operands = new List<AsmOperand>();
        if (operandText.Length > 0)
        {
            foreach (string part in SplitOperands(operandText))
            {
                if (!TryParseOperand(part, out AsmOperand operand, out error))
                    return false;
                operands.Add(operand);
            }
        }

        parsed = new ParsedInstruction(canonical, operands.ToArray(), lockPrefix, BranchMnemonics.Contains(canonical));
        return true;
    }

    private static IEnumerable<string> SplitOperands(string text)
    {
        int depth = 0;
        int start = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '[') depth++;
            else if (c == ']') depth--;
            else if (c == ',' && depth == 0)
            {
                yield return text[start..i].Trim();
                start = i + 1;
            }
        }
        yield return text[start..].Trim();
    }

    private bool TryParseOperand(string text, out AsmOperand operand, out string error)
    {
        operand = default!;
        error = string.Empty;
        text = text.Trim();

        int? size = null;
        foreach ((string hint, int bits) in SizeHints)
        {
            if (text.StartsWith(hint, StringComparison.OrdinalIgnoreCase))
            {
                string rest = text[hint.Length..].TrimStart();
                if (rest.StartsWith("ptr", StringComparison.OrdinalIgnoreCase))
                    rest = rest[3..].TrimStart();
                size = bits;
                text = rest;
                break;
            }
        }

        if (text.StartsWith('[') && text.EndsWith(']'))
        {
            if (!TryParseMemory(text[1..^1], size, out MemoryOperand memory, out error))
                return false;
            operand = new MemOperand(size, memory);
            return true;
        }

        if (_registers.TryGetValue(text, out Register register))
        {
            operand = new RegOperand(_registerSizes[text], register);
            return true;
        }

        if (TryParseNumber(text, out ImmOperand imm))
        {
            operand = imm;
            return true;
        }

        error = $"Unrecognized operand '{text}'.";
        return false;
    }

    private static bool TryParseMemory(string expression, int? size, out MemoryOperand memory, out string error)
    {
        memory = default;
        error = string.Empty;

        Register @base = Register.None;
        Register index = Register.None;
        int scale = 1;
        long displacement = 0;

        int i = 0;
        int sign = 1;
        while (i < expression.Length)
        {
            char c = expression[i];
            if (c == '+') { sign = 1; i++; continue; }
            if (c == '-') { sign = -1; i++; continue; }
            if (char.IsWhiteSpace(c)) { i++; continue; }

            int start = i;
            while (i < expression.Length && expression[i] != '+' && expression[i] != '-' && !char.IsWhiteSpace(expression[i]))
                i++;
            string token = expression[start..i].Trim();
            if (token.Length == 0)
                continue;

            int star = token.IndexOf('*');
            if (star >= 0)
            {
                string left = token[..star].Trim();
                string right = token[(star + 1)..].Trim();

                if (TryParseNumberCore(right, out long rightValue) && _registers.TryGetValue(left, out Register idx))
                {
                    index = idx;
                    scale = (int)rightValue;
                }
                else if (TryParseNumberCore(left, out long leftValue) && _registers.TryGetValue(right, out idx))
                {
                    index = idx;
                    scale = (int)leftValue;
                }
                else
                {
                    error = $"Invalid scaled index '{token}'.";
                    return false;
                }

                if (scale is not (1 or 2 or 4 or 8))
                {
                    error = "Index scale must be 1, 2, 4 or 8.";
                    return false;
                }
            }
            else if (_registers.TryGetValue(token, out Register reg))
            {
                if (@base == Register.None)
                {
                    @base = reg;
                }
                else if (index == Register.None)
                {
                    index = reg;
                }
                else
                {
                    error = "Too many registers in the memory operand.";
                    return false;
                }
            }
            else if (TryParseNumberCore(token, out long value))
            {
                displacement += sign * value;
            }
            else
            {
                error = $"Unrecognized memory token '{token}'.";
                return false;
            }
        }

        int displSize = 0;
        if (displacement != 0)
            displSize = displacement >= sbyte.MinValue && displacement <= sbyte.MaxValue ? 1 : 4;

        MemoryOperand memoryOperand;
        if (@base != Register.None && index != Register.None)
            memoryOperand = new MemoryOperand(@base, index, scale == 0 ? 1 : scale, displacement, displSize);
        else if (@base != Register.None)
            memoryOperand = new MemoryOperand(@base, displacement, displSize);
        else if (index != Register.None)
            memoryOperand = new MemoryOperand(index, scale == 0 ? 1 : scale, displacement, displSize);
        else
            memoryOperand = new MemoryOperand(unchecked((ulong)displacement), displSize);

        memory = memoryOperand;
        return true;
    }

    private static readonly (string Hint, int Bits)[] SizeHints =
    {
        ("byte", 8), ("word", 16), ("dword", 32), ("qword", 64)
    };

    private static bool TryParseNumber(string text, out ImmOperand operand)
    {
        operand = default!;
        text = text.Trim();
        if (text.Length == 0)
            return false;

        bool negative = false;
        if (text[0] is '+' or '-')
        {
            negative = text[0] == '-';
            text = text[1..];
        }

        ulong value;
        bool hex = false;

        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            hex = true;
            if (!ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value))
                return false;
        }
        else if (text.EndsWith('h') &&
                 ulong.TryParse(text.AsSpan(0, text.Length - 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value))
        {
            hex = true;
        }
        else if (!ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
        {
            return false;
        }

        operand = new ImmOperand(negative, value, hex);
        return true;
    }

    private static bool TryParseNumberCore(string text, out long value)
    {
        value = 0;
        if (!TryParseNumber(text, out ImmOperand imm))
            return false;
        if (imm.Negative && imm.Magnitude > 0x8000000000000000UL)
            return false;
        value = RawLong(imm);
        return true;
    }

    // ---------- Static tables ----------

    private static readonly HashSet<string> BranchMnemonics = new(StringComparer.OrdinalIgnoreCase)
    {
        "jmp", "call", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
        "ja", "jae", "jb", "jbe", "jc", "jnc", "jo", "jno", "js", "jns",
        "jp", "jnp", "jpe", "jpo", "loop", "loope", "loopne", "loopz", "loopnz"
    };

    private static readonly Dictionary<string, Register> _registers = BuildRegisters();
    private static readonly Dictionary<string, int> _registerSizes = BuildRegisterSizes();
    private static readonly Dictionary<string, Mnemonic> _mnemonics = BuildMnemonics();
    private static readonly Dictionary<string, List<Code>> _codesByMnemonic = BuildCodes();

    private static Dictionary<string, Register> BuildRegisters()
    {
        var result = new Dictionary<string, Register>(StringComparer.OrdinalIgnoreCase);
        Type[] gprTypes = { typeof(AssemblerRegister8), typeof(AssemblerRegister16), typeof(AssemblerRegister32), typeof(AssemblerRegister64) };

        foreach (FieldInfo field in typeof(AssemblerRegisters).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (!gprTypes.Contains(field.FieldType))
                continue;
            if (Enum.TryParse(field.Name, ignoreCase: true, out Register register))
                result[field.Name] = register;
        }

        return result;
    }

    private static Dictionary<string, int> BuildRegisterSizes()
    {
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (FieldInfo field in typeof(AssemblerRegisters).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            int size = field.FieldType == typeof(AssemblerRegister8) ? 8
                : field.FieldType == typeof(AssemblerRegister16) ? 16
                : field.FieldType == typeof(AssemblerRegister32) ? 32
                : field.FieldType == typeof(AssemblerRegister64) ? 64
                : 0;
            if (size != 0)
                result[field.Name] = size;
        }

        return result;
    }

    private static Dictionary<string, Mnemonic> BuildMnemonics()
    {
        var result = new Dictionary<string, Mnemonic>(StringComparer.OrdinalIgnoreCase);
        foreach (Mnemonic mnemonic in Enum.GetValues<Mnemonic>())
            result[mnemonic.ToString()] = mnemonic;

        AddAlias(result, "sal", "shl");
        AddAlias(result, "jz", "je");
        AddAlias(result, "jnz", "jne");
        AddAlias(result, "jc", "jb");
        AddAlias(result, "jnc", "jae");
        AddAlias(result, "jna", "jbe");
        AddAlias(result, "jnae", "jb");
        AddAlias(result, "jnb", "jae");
        AddAlias(result, "jnbe", "ja");
        AddAlias(result, "setz", "sete");
        AddAlias(result, "setnz", "setne");
        AddAlias(result, "setc", "setb");
        AddAlias(result, "setnc", "setae");
        return result;
    }

    private static void AddAlias(Dictionary<string, Mnemonic> map, string alias, string target)
    {
        if (!map.ContainsKey(alias) && map.TryGetValue(target, out Mnemonic mnemonic))
            map[alias] = mnemonic;
    }

    private static Dictionary<string, List<Code>> BuildCodes()
    {
        var result = new Dictionary<string, List<Code>>(StringComparer.OrdinalIgnoreCase);
        foreach (Code code in Enum.GetValues<Code>())
        {
            OpCodeInfo info;
            try
            {
                info = code.ToOpCode();
            }
            catch (Exception)
            {
                continue;
            }

            string name = info.Mnemonic.ToString();
            if (!result.TryGetValue(name, out List<Code>? list))
            {
                list = new List<Code>();
                result[name] = list;
            }
            list.Add(code);
        }

        // movsx and movsxd share the mnemonic in most assemblers.
        if (result.TryGetValue("movsxd", out List<Code>? movsxd) &&
            result.TryGetValue("movsx", out List<Code>? movsx))
        {
            movsx.AddRange(movsxd);
        }

        return result;
    }

    private static IEnumerable<Code> GetBranchCodes(string mnemonic)
    {
        if (!_codesByMnemonic.TryGetValue(mnemonic, out List<Code>? codes))
            yield break;

        foreach (Code code in codes.Where(c =>
                     c.ToString().EndsWith("_64", StringComparison.OrdinalIgnoreCase) &&
                     c.ToString().Contains("rel", StringComparison.OrdinalIgnoreCase))
                 .OrderBy(c => c.ToString().Contains("rel8", StringComparison.OrdinalIgnoreCase) ? 0 : 1))
        {
            yield return code;
        }
    }

    // ---------- Types ----------

    private sealed record ParsedInstruction(string Mnemonic, AsmOperand[] Operands, bool Lock, bool Branch);

    private abstract record AsmOperand;

    private sealed record RegOperand(int Size, Register Register) : AsmOperand;

    private sealed record ImmOperand(bool Negative, ulong Magnitude, bool Hex) : AsmOperand;

    private sealed record MemOperand(int? Size, MemoryOperand Memory) : AsmOperand;

    private sealed class ByteCodeWriter : CodeWriter
    {
        private readonly List<byte> _bytes = new();

        public override void WriteByte(byte value) => _bytes.Add(value);

        public byte[] ToArray() => _bytes.ToArray();
    }
}
