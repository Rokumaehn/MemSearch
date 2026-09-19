using System.ComponentModel;

namespace OmniHax;

/// <summary>
/// One scanned address shown in the result grid. Assigning <see cref="Value"/>
/// writes the parsed value back into the target process memory.
/// </summary>
public sealed class ResultRow : INotifyPropertyChanged
{
    private readonly Func<ulong, string, (bool Ok, string Applied, string? Error)> _writer;
    private string _value;

    public ResultRow(ulong address, string value, Func<ulong, string, (bool Ok, string Applied, string? Error)> writer)
    {
        AddressValue = address;
        _value = value;
        _writer = writer;
    }

    public ulong AddressValue { get; }

    public string Address => $"0x{AddressValue:X}";

    public string Value
    {
        get => _value;
        set
        {
            if (value == _value)
                return;

            (bool ok, string applied, string? error) = _writer(AddressValue, value);
            if (ok)
                _value = applied;

            OnPropertyChanged(nameof(Value));

            if (!ok && error is not null)
                WriteFailed?.Invoke(error);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action<string>? WriteFailed;

    private void OnPropertyChanged(string name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
