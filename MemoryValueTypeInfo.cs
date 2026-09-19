using System.Buffers.Binary;
using System.Globalization;

namespace OmniHax;

internal enum MemoryValueType
{
    Byte,
    SByte,
    Word,
    Int16,
    DWord,
    Int32,
    QWord,
    Int64,
    Float,
    Double
}

internal sealed record ValueTypeOption(MemoryValueType Type, string DisplayName);

internal static class MemoryValueTypeInfo
{
    private static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;

    public static readonly MemoryValueType[] AllTypes =
    {
        MemoryValueType.Byte, MemoryValueType.SByte,
        MemoryValueType.Word, MemoryValueType.Int16,
        MemoryValueType.DWord, MemoryValueType.Int32,
        MemoryValueType.QWord, MemoryValueType.Int64,
        MemoryValueType.Float, MemoryValueType.Double
    };

    public static readonly ValueTypeOption[] Options =
        AllTypes.Select(t => new ValueTypeOption(t, DisplayName(t))).ToArray();

    public static int SizeOf(MemoryValueType type) => type switch
    {
        MemoryValueType.Byte or MemoryValueType.SByte => 1,
        MemoryValueType.Word or MemoryValueType.Int16 => 2,
        MemoryValueType.DWord or MemoryValueType.Int32 or MemoryValueType.Float => 4,
        MemoryValueType.QWord or MemoryValueType.Int64 or MemoryValueType.Double => 8,
        _ => 0
    };

    public static string DisplayName(MemoryValueType type) => type switch
    {
        MemoryValueType.Byte => "Byte (8-bit unsigned)",
        MemoryValueType.SByte => "SByte (8-bit signed)",
        MemoryValueType.Word => "Word (16-bit unsigned)",
        MemoryValueType.Int16 => "Int16 (16-bit signed)",
        MemoryValueType.DWord => "DWord (32-bit unsigned)",
        MemoryValueType.Int32 => "Int32 (32-bit signed)",
        MemoryValueType.QWord => "QWord (64-bit unsigned)",
        MemoryValueType.Int64 => "Int64 (64-bit signed)",
        MemoryValueType.Float => "Float (32-bit)",
        MemoryValueType.Double => "Double (64-bit)",
        _ => type.ToString()
    };

    /// <summary>
    /// Parses the user supplied text into the little-endian byte pattern for the
    /// selected datatype and returns a normalized display string.
    /// </summary>
    public static bool TryParse(MemoryValueType type, string? text, out byte[] bytes, out string normalized, out string error)
    {
        bytes = Array.Empty<byte>();
        normalized = string.Empty;
        error = string.Empty;

        text = (text ?? string.Empty).Trim();
        if (text.Length == 0)
        {
            error = "Enter a value to search for.";
            return false;
        }

        switch (type)
        {
            case MemoryValueType.Byte:
                if (!TryParseUnsigned(text, byte.MaxValue, out ulong b, out error)) return false;
                bytes = new[] { (byte)b };
                normalized = b.ToString(Invariant);
                return true;

            case MemoryValueType.SByte:
                if (!TryParseSigned(text, sbyte.MinValue, sbyte.MaxValue, out long sb, out error)) return false;
                bytes = new byte[1];
                bytes[0] = unchecked((byte)(sbyte)sb);
                normalized = sb.ToString(Invariant);
                return true;

            case MemoryValueType.Word:
                if (!TryParseUnsigned(text, ushort.MaxValue, out ulong w, out error)) return false;
                bytes = new byte[2];
                BinaryPrimitives.WriteUInt16LittleEndian(bytes, (ushort)w);
                normalized = w.ToString(Invariant);
                return true;

            case MemoryValueType.Int16:
                if (!TryParseSigned(text, short.MinValue, short.MaxValue, out long i16, out error)) return false;
                bytes = new byte[2];
                BinaryPrimitives.WriteInt16LittleEndian(bytes, (short)i16);
                normalized = i16.ToString(Invariant);
                return true;

            case MemoryValueType.DWord:
                if (!TryParseUnsigned(text, uint.MaxValue, out ulong dw, out error)) return false;
                bytes = new byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(bytes, (uint)dw);
                normalized = dw.ToString(Invariant);
                return true;

            case MemoryValueType.Int32:
                if (!TryParseSigned(text, int.MinValue, int.MaxValue, out long i32, out error)) return false;
                bytes = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(bytes, (int)i32);
                normalized = i32.ToString(Invariant);
                return true;

            case MemoryValueType.QWord:
                if (!TryParseUnsigned(text, ulong.MaxValue, out ulong qw, out error)) return false;
                bytes = new byte[8];
                BinaryPrimitives.WriteUInt64LittleEndian(bytes, qw);
                normalized = qw.ToString(Invariant);
                return true;

            case MemoryValueType.Int64:
                if (!TryParseSigned(text, long.MinValue, long.MaxValue, out long i64, out error)) return false;
                bytes = new byte[8];
                BinaryPrimitives.WriteInt64LittleEndian(bytes, i64);
                normalized = i64.ToString(Invariant);
                return true;

            case MemoryValueType.Float:
                if (!float.TryParse(text, NumberStyles.Float, Invariant, out float f))
                {
                    error = "Enter a valid 32-bit floating point number.";
                    return false;
                }
                bytes = new byte[4];
                BinaryPrimitives.WriteSingleLittleEndian(bytes, f);
                normalized = f.ToString("R", Invariant);
                return true;

            case MemoryValueType.Double:
                if (!double.TryParse(text, NumberStyles.Float, Invariant, out double d))
                {
                    error = "Enter a valid 64-bit floating point number.";
                    return false;
                }
                bytes = new byte[8];
                BinaryPrimitives.WriteDoubleLittleEndian(bytes, d);
                normalized = d.ToString("R", Invariant);
                return true;

            default:
                error = "Unsupported datatype.";
                return false;
        }
    }

    public static string Format(MemoryValueType type, ReadOnlySpan<byte> data) => type switch
    {
        MemoryValueType.Byte => data[0].ToString(Invariant),
        MemoryValueType.SByte => ((sbyte)data[0]).ToString(Invariant),
        MemoryValueType.Word => BinaryPrimitives.ReadUInt16LittleEndian(data).ToString(Invariant),
        MemoryValueType.Int16 => BinaryPrimitives.ReadInt16LittleEndian(data).ToString(Invariant),
        MemoryValueType.DWord => BinaryPrimitives.ReadUInt32LittleEndian(data).ToString(Invariant),
        MemoryValueType.Int32 => BinaryPrimitives.ReadInt32LittleEndian(data).ToString(Invariant),
        MemoryValueType.QWord => BinaryPrimitives.ReadUInt64LittleEndian(data).ToString(Invariant),
        MemoryValueType.Int64 => BinaryPrimitives.ReadInt64LittleEndian(data).ToString(Invariant),
        MemoryValueType.Float => BinaryPrimitives.ReadSingleLittleEndian(data).ToString("R", Invariant),
        MemoryValueType.Double => BinaryPrimitives.ReadDoubleLittleEndian(data).ToString("R", Invariant),
        _ => "??"
    };

    /// <summary>
    /// Compares two raw little-endian values (zero-extended to 64 bits) for the
    /// given datatype, returning a negative value, zero or a positive value.
    /// </summary>
    public static int Compare(MemoryValueType type, ulong left, ulong right) => type switch
    {
        MemoryValueType.Byte => ((byte)left).CompareTo((byte)right),
        MemoryValueType.SByte => ((sbyte)left).CompareTo((sbyte)right),
        MemoryValueType.Word => ((ushort)left).CompareTo((ushort)right),
        MemoryValueType.Int16 => ((short)left).CompareTo((short)right),
        MemoryValueType.DWord => ((uint)left).CompareTo((uint)right),
        MemoryValueType.Int32 => ((int)left).CompareTo((int)right),
        MemoryValueType.QWord => left.CompareTo(right),
        MemoryValueType.Int64 => ((long)left).CompareTo((long)right),
        MemoryValueType.Float => BitConverter.UInt32BitsToSingle((uint)left)
            .CompareTo(BitConverter.UInt32BitsToSingle((uint)right)),
        MemoryValueType.Double => BitConverter.UInt64BitsToDouble(left)
            .CompareTo(BitConverter.UInt64BitsToDouble(right)),
        _ => left.CompareTo(right)
    };

    private static bool TryParseUnsigned(string text, ulong max, out ulong value, out string error)
    {
        error = string.Empty;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!ulong.TryParse(text.AsSpan(2), NumberStyles.AllowHexSpecifier, Invariant, out value))
            {
                error = "Enter a valid hexadecimal number (for example 0x1F).";
                return false;
            }
        }
        else if (!ulong.TryParse(text, NumberStyles.Integer, Invariant, out value))
        {
            error = "Enter a valid whole number.";
            return false;
        }

        if (value > max)
        {
            error = $"Value must be between 0 and {max}.";
            return false;
        }

        return true;
    }

    private static bool TryParseSigned(string text, long min, long max, out long value, out string error)
    {
        error = string.Empty;
        value = 0;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!ulong.TryParse(text.AsSpan(2), NumberStyles.AllowHexSpecifier, Invariant, out ulong raw))
            {
                error = "Enter a valid hexadecimal number (for example 0x1F).";
                return false;
            }
            value = unchecked((long)raw);
        }
        else if (!long.TryParse(text, NumberStyles.Integer, Invariant, out value))
        {
            error = "Enter a valid whole number.";
            return false;
        }

        if (value < min || value > max)
        {
            error = $"Value must be between {min} and {max}.";
            return false;
        }

        return true;
    }
}
