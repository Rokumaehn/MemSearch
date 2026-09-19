using System.ComponentModel;
using System.Globalization;

namespace MemSearch;

public enum CodeDataType
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
    Double,
    Script
}

public sealed record CodeDataTypeOption(CodeDataType Type, string DisplayName);

public static class CodeDataTypeInfo
{
    public static IReadOnlyList<CodeDataTypeOption> Options { get; } = BuildOptions();

    private static IReadOnlyList<CodeDataTypeOption> BuildOptions()
    {
        var options = new List<CodeDataTypeOption>();
        foreach (ValueTypeOption option in MemoryValueTypeInfo.Options)
            options.Add(new CodeDataTypeOption((CodeDataType)option.Type, option.DisplayName));

        options.Add(new CodeDataTypeOption(CodeDataType.Script, "Script"));
        return options;
    }

    internal static MemoryValueType? ToMemoryValueType(CodeDataType type) =>
        type == CodeDataType.Script ? null : (MemoryValueType)type;
}

/// <summary>
/// One editable entry in the Codes tab. Non-script entries are periodically
/// written to the target; script entries inject assembly when enabled and
/// restore the original bytes when disabled.
/// </summary>
public sealed class CodeEntry : INotifyPropertyChanged
{
    private string _description;
    private string _address;
    private string _value;
    private string _scriptText;
    private CodeDataType _dataType;
    private bool _enabled;
    private string? _lastError;

    public CodeEntry(ulong address, CodeDataType dataType, string value, string scriptText, string description)
    {
        AddressValue = address;
        _address = $"0x{address:X}";
        _dataType = dataType;
        _value = value;
        _scriptText = scriptText;
        _description = description;
    }

    public ulong AddressValue { get; private set; }

    public string Address
    {
        get => _address;
        set
        {
            if (_address == value)
                return;

            if (TryParseAddress(value, out ulong parsed))
                AddressValue = parsed;

            _address = value;
            OnPropertyChanged(nameof(Address));
            OnPropertyChanged(nameof(AddressValue));
        }
    }

    public string Description
    {
        get => _description;
        set
        {
            if (_description == value)
                return;
            _description = value;
            OnPropertyChanged(nameof(Description));
        }
    }

    public CodeDataType DataType
    {
        get => _dataType;
        set
        {
            if (_dataType == value)
                return;
            _dataType = value;
            OnPropertyChanged(nameof(DataType));
            OnPropertyChanged(nameof(IsScript));
            OnPropertyChanged(nameof(Value));
        }
    }

    public bool IsScript => _dataType == CodeDataType.Script;

    public bool Enabled
    {
        get => _enabled;
        set
        {
            if (_enabled == value)
                return;
            _enabled = value;
            OnPropertyChanged(nameof(Enabled));
        }
    }

    public string Value
    {
        get => IsScript ? "<asm>" : _value;
        set
        {
            if (IsScript || _value == value)
                return;
            _value = value;
            OnPropertyChanged(nameof(Value));
        }
    }

    public string ScriptText
    {
        get => _scriptText;
        set
        {
            if (_scriptText == value)
                return;
            _scriptText = value;
            OnPropertyChanged(nameof(ScriptText));
        }
    }

    public string? LastError
    {
        get => _lastError;
        set
        {
            if (_lastError == value)
                return;
            _lastError = value;
            OnPropertyChanged(nameof(LastError));
        }
    }

    internal EditResult? Applied { get; set; }

    public IReadOnlyList<CodeDataTypeOption> DataTypeOptions => CodeDataTypeInfo.Options;

    public static bool TryParseAddress(string? text, out ulong address)
    {
        address = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address);

        return ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address)
            || ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out address);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged(string name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
