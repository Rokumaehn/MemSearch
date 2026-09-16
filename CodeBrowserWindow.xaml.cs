using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Iced.Intel;

namespace MemSearch;

public sealed class CodeRow
{
    public ulong AddressValue { get; init; }
    public string Address { get; init; } = string.Empty;
    public string Bytes { get; init; } = string.Empty;
    public int Length { get; init; }
    public string Text { get; set; } = string.Empty;
    public bool IsHighlighted { get; init; }
    public bool IsCurrent { get; init; }
    public Instruction Instruction { get; init; }
}

public partial class CodeBrowserWindow : Window
{
    private readonly ProcessMemory _memory;
    private readonly DisassemblyService _disassembly;
    private readonly AssemblerService _assembler;
    private readonly ulong? _highlight;
    private readonly ObservableCollection<CodeRow> _rows = new();
    private readonly Stack<ulong> _history = new();

    private ulong _current;

    internal CodeBrowserWindow(ProcessMemory memory, DisassemblyService disassembly, AssemblerService assembler,
        ulong address, ulong? highlight)
    {
        InitializeComponent();

        _memory = memory;
        _disassembly = disassembly;
        _assembler = assembler;
        _highlight = highlight;
        _current = address;

        CodeGrid.ItemsSource = _rows;
        Reload();
    }

    private void Reload()
    {
        _rows.Clear();

        foreach (DisassembledInstruction instruction in _disassembly.DecodeBackward(_memory, _current, 8))
            _rows.Add(MakeRow(instruction));

        foreach (DisassembledInstruction instruction in _disassembly.DecodeForward(_memory, _current, 80, 2048))
            _rows.Add(MakeRow(instruction));

        GoAddressBox.Text = $"0x{_current:X}";

        CodeRow? currentRow = _rows.FirstOrDefault(r => r.IsCurrent);
        if (currentRow is not null)
        {
            CodeGrid.SelectedItem = currentRow;
            CodeGrid.ScrollIntoView(currentRow);
        }
    }

    private CodeRow MakeRow(DisassembledInstruction instruction) => new()
    {
        AddressValue = instruction.Address,
        Address = $"0x{instruction.Address:X}",
        Bytes = string.Join(' ', instruction.Bytes.Select(b => b.ToString("X2"))),
        Length = instruction.Length,
        Text = instruction.Text,
        IsHighlighted = _highlight is ulong h && h == instruction.Address,
        IsCurrent = instruction.Address == _current,
        Instruction = instruction.Instruction
    };

    private void Navigate(ulong address, bool pushHistory)
    {
        if (pushHistory)
            _history.Push(_current);
        _current = address;
        Reload();
    }

    private void GoButton_Click(object sender, RoutedEventArgs e) => GoToTypedAddress();

    private void GoAddressBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            GoToTypedAddress();
        }
    }

    private void GoToTypedAddress()
    {
        string text = GoAddressBox.Text.Trim();
        if (TryParseAddress(text, out ulong address))
            Navigate(address, pushHistory: true);
        else
            StatusText.Text = $"Invalid address '{text}'.";
    }

    private static bool TryParseAddress(string text, out ulong address)
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

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        if (_history.Count == 0)
        {
            StatusText.Text = "No previous location.";
            return;
        }

        _current = _history.Pop();
        Reload();
    }

    private void FollowButton_Click(object sender, RoutedEventArgs e)
    {
        if (CodeGrid.SelectedItem is not CodeRow row)
            return;

        if (DisassemblyService.TryGetBranchTarget(row.Instruction, out ulong target))
        {
            Navigate(target, pushHistory: true);
        }
        else
        {
            StatusText.Text = "The selected instruction is not a direct branch or call.";
        }
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e) => Reload();

    private void CodeGrid_PreparingCellForEdit(object sender, DataGridPreparingCellForEditEventArgs e)
    {
        if (e.Column != InstructionColumn)
            return;

        if (e.EditingElement is TextBox textBox)
        {
            textBox.SelectAll();
            textBox.Focus();
        }
    }

    private void CodeGrid_CellEditEnding(object sender, DataGridCellEditEndingEventArgs e)
    {
        if (e.EditAction != DataGridEditAction.Commit || e.Column != InstructionColumn)
            return;

        if (e.Row.Item is not CodeRow row || e.EditingElement is not TextBox textBox)
            return;

        string text = textBox.Text.Trim();
        if (text.Length == 0 || text == row.Text)
            return;

        EditResult result = _assembler.Apply(row.AddressValue, text);
        StatusText.Text = result.Success ? result.Message : $"Error: {result.Message}";

        // Always refresh so a failed edit reverts to the real disassembly.
        Dispatcher.BeginInvoke(new Action(Reload));
    }
}
