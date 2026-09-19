using System.Collections.ObjectModel;

namespace MemSearch;

/// <summary>
/// Holds the list of code entries, applies/reverts script injections and
/// periodically writes enabled non-script values into the target.
/// </summary>
internal sealed class CodeManager
{
    private readonly ProcessMemory _memory;
    private readonly AssemblerService _assembler;

    public CodeManager(ProcessMemory memory, AssemblerService assembler)
    {
        _memory = memory;
        _assembler = assembler;
    }

    public ObservableCollection<CodeEntry> Entries { get; } = new();

    public CodeEntry AddData(ulong address, MemoryValueType type, string value, string description)
    {
        var entry = new CodeEntry(address, (CodeDataType)type, value, string.Empty, description);
        Entries.Add(entry);
        return entry;
    }

    public CodeEntry AddScript(ulong address, string scriptText, string description)
    {
        var entry = new CodeEntry(address, CodeDataType.Script, string.Empty, scriptText, description);
        Entries.Add(entry);
        return entry;
    }

    public bool IsAddressActive(CodeEntry candidate)
    {
        foreach (CodeEntry entry in Entries)
        {
            if (!ReferenceEquals(entry, candidate) && entry.Enabled && entry.AddressValue == candidate.AddressValue)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Applies an entry that has just been enabled. Returns false and sets
    /// <see cref="CodeEntry.LastError"/> if the entry could not be applied.
    /// </summary>
    public bool Apply(CodeEntry entry)
    {
        if (entry.IsScript)
            return ApplyScript(entry);

        return WriteData(entry);
    }

    /// <summary>Reverts an enabled script entry (data entries need no revert).</summary>
    public void Revert(CodeEntry entry)
    {
        EditResult? applied = entry.Applied;
        if (applied is null)
            return;

        if (applied.OriginalBytes is { Length: > 0 })
            _memory.WriteCode(applied.PatchAddress, applied.OriginalBytes);

        if (applied.Mode == EditMode.CodeCave && applied.CaveAddress != 0)
            _memory.FreeMemory(applied.CaveAddress);

        entry.Applied = null;
    }

    /// <summary>Periodically writes every enabled non-script entry.</summary>
    public void OnTick()
    {
        foreach (CodeEntry entry in Entries)
        {
            if (entry.Enabled && !entry.IsScript)
                WriteData(entry);
        }
    }

    public void Remove(CodeEntry entry)
    {
        Revert(entry);
        Entries.Remove(entry);
    }

    private bool ApplyScript(CodeEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.ScriptText))
        {
            entry.LastError = "The script is empty.";
            return false;
        }

        EditResult result = _assembler.Apply(entry.AddressValue, entry.ScriptText);
        if (!result.Success)
        {
            entry.LastError = result.Message;
            return false;
        }

        entry.Applied = result;
        entry.LastError = null;
        return true;
    }

    private bool WriteData(CodeEntry entry)
    {
        MemoryValueType? type = CodeDataTypeInfo.ToMemoryValueType(entry.DataType);
        if (type is null)
            return false;

        if (!MemoryValueTypeInfo.TryParse(type.Value, entry.Value, out byte[] bytes, out _, out string error))
        {
            entry.LastError = error;
            return false;
        }

        if (!_memory.WriteBytes(entry.AddressValue, bytes))
        {
            entry.LastError = $"Failed to write to 0x{entry.AddressValue:X}.";
            return false;
        }

        entry.LastError = null;
        return true;
    }
}
