using System.Windows;
using System.Windows.Controls;

namespace MemSearch;

public partial class ScriptEditorWindow : Window
{
    private readonly ProcessMemory _memory;
    private readonly DisassemblyService _disassembly;
    private readonly AssemblerService _assembler;
    private readonly CodeEntry _entry;

    internal ScriptEditorWindow(ProcessMemory memory, DisassemblyService disassembly, AssemblerService assembler, CodeEntry entry)
    {
        InitializeComponent();

        _memory = memory;
        _disassembly = disassembly;
        _assembler = assembler;
        _entry = entry;

        ScriptBox.Text = entry.ScriptText;
        HeaderText.Text = $"Target 0x{entry.AddressValue:X}. Original instruction length: {OriginalLength()} byte(s).";
        UpdatePreview();
    }

    private int OriginalLength()
    {
        List<DisassembledInstruction> list = _disassembly.DecodeForward(_memory, _entry.AddressValue, 1, 16);
        return list.Count > 0 ? list[0].Length : 0;
    }

    private void ScriptBox_TextChanged(object sender, TextChangedEventArgs e) => UpdatePreview();

    private void UpdatePreview()
    {
        string text = ScriptBox.Text.Trim();
        if (text.Length == 0)
        {
            PreviewText.Text = "Enter an instruction.";
            return;
        }

        if (!_assembler.TryAssemble(text, _entry.AddressValue, out byte[] bytes, out string error))
        {
            PreviewText.Text = $"Cannot assemble: {error}";
            return;
        }

        int original = OriginalLength();
        PreviewText.Text = bytes.Length <= original
            ? $"{bytes.Length} byte(s): fits in place ({original - bytes.Length} NOP filler)."
            : $"{bytes.Length} byte(s): does not fit in {original} byte(s); a code cave with a jump trampoline will be used.";
    }

    private void OkButton_Click(object sender, RoutedEventArgs e)
    {
        _entry.ScriptText = ScriptBox.Text.Trim();
        DialogResult = true;
    }
}
