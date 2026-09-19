using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemSearch;

public partial class MainWindow : Window
{
    private const int ResultThreshold = 100;

    private readonly ObservableCollection<ResultRow> _results = new();
    private readonly object _scanLock = new();

    private ProcessMemory? _memory;
    private MemoryScanner? _scanner;
    private DisassemblyService? _disassembly;
    private AssemblerService? _assembler;
    private CodeManager? _codes;
    private DispatcherTimer? _freezeTimer;
    private CancellationTokenSource? _cts;
    private bool _typeLocked;
    private bool _isScanning;
    private AccessMechanism _accessMechanism = AccessMechanism.InProcessVeh;

    public MainWindow()
    {
        InitializeComponent();

        ResultsGrid.ItemsSource = _results;

        TypeCombo.ItemsSource = MemoryValueTypeInfo.Options;
        TypeCombo.DisplayMemberPath = nameof(ValueTypeOption.DisplayName);
        TypeCombo.SelectedValuePath = nameof(ValueTypeOption.Type);
        TypeCombo.SelectedValue = MemoryValueType.DWord;

        UpdateAccessTypeChecks();
        StartFreezeTimer();
    }

    private void StartFreezeTimer()
    {
        _freezeTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _freezeTimer.Tick += (_, _) => _codes?.OnTick();
        _freezeTimer.Start();
    }

    private void OpenProcessButton_Click(object sender, RoutedEventArgs e) => OpenProcess();

    private void OpenProcessMenuItem_Click(object sender, RoutedEventArgs e) => OpenProcess();

    private void OpenProcess()
    {
        var picker = new ProcessPickerWindow { Owner = this };
        if (picker.ShowDialog() == true && picker.SelectedProcess is ProcessItem item)
            AttachProcess(item);
    }

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e) => Close();

    private void AccessType_Click(object sender, RoutedEventArgs e)
    {
        if (ReferenceEquals(sender, AccessTypeHw))
            _accessMechanism = AccessMechanism.HardwareBreakpoints;
        else if (ReferenceEquals(sender, AccessTypeGuard))
            _accessMechanism = AccessMechanism.GuardPage;
        else
            _accessMechanism = AccessMechanism.InProcessVeh;

        UpdateAccessTypeChecks();
    }

    private void UpdateAccessTypeChecks()
    {
        AccessTypeHw.IsChecked = _accessMechanism == AccessMechanism.HardwareBreakpoints;
        AccessTypeGuard.IsChecked = _accessMechanism == AccessMechanism.GuardPage;
        AccessTypeVeh.IsChecked = _accessMechanism == AccessMechanism.InProcessVeh;
    }

    private void AttachProcess(ProcessItem item)
    {
        try
        {
            _memory?.Dispose();
            _memory = ProcessMemory.Open(item.Id, item.Name);

            int bitness = _memory.Is64BitProcess ? 64 : 32;
            _disassembly = new DisassemblyService(bitness);
            _assembler = new AssemblerService(_memory, _disassembly, bitness);

            _codes = new CodeManager(_memory, _assembler);
            CodesGrid.ItemsSource = _codes.Entries;

            ProcessLabel.Text = $"{item.Name} (PID {item.Id})";
            ResetSearch();
        }
        catch (Win32Exception ex)
        {
            MessageBox.Show(this,
                $"Could not open {item.Name} (PID {item.Id}).\n\n{ex.Message}",
                "Open Process", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SearchButton_Click(object sender, RoutedEventArgs e) => _ = StartScanAsync();

    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            _ = StartScanAsync();
        }
    }

    private void ResetButton_Click(object sender, RoutedEventArgs e) => ResetSearch();

    private void ResetSearch()
    {
        _cts?.Cancel();

        lock (_scanLock)
        {
            _scanner = null;
            _typeLocked = false;
        }

        _results.Clear();
        TypeCombo.IsEnabled = true;
        SearchBox.IsEnabled = true;
        SearchButton.IsEnabled = true;

        StatusText.Text = _memory is null
            ? "Open a process to begin."
            : "Ready. Choose a type, enter a value and press Search.";
    }

    private async Task StartScanAsync()
    {
        if (_isScanning)
            return;

        if (_memory is null)
        {
            MessageBox.Show(this, "Open a process first.", "MemSearch",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (TypeCombo.SelectedValue is not MemoryValueType type)
            return;

        string searchText = SearchBox.Text;
        if (string.IsNullOrWhiteSpace(searchText))
        {
            StatusText.Text = "Enter a value to search for.";
            return;
        }

        MemoryScanner scanner;
        lock (_scanLock)
        {
            if (!_typeLocked || _scanner is null)
                _scanner = new MemoryScanner(_memory, type);
            scanner = _scanner;
        }

        _isScanning = true;
        _cts = new CancellationTokenSource();
        SearchButton.IsEnabled = false;
        SearchBox.IsEnabled = false;
        ScanProgress.Visibility = Visibility.Visible;
        StatusText.Text = "Scanning...";

        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                StatusText.Text = $"Scanning... {p.RegionsDone}/{p.RegionsTotal} regions, {p.Found} match(es).";
            });

            IReadOnlyList<ulong> results = await scanner.ScanAsync(searchText, progress, _cts.Token);

            if (!_typeLocked)
            {
                _typeLocked = true;
                TypeCombo.IsEnabled = false;
            }

            UpdateResults(results);
        }
        catch (FormatException ex)
        {
            StatusText.Text = "Invalid value.";
            MessageBox.Show(this, ex.Message, "Invalid Value",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan cancelled.";
        }
        finally
        {
            _isScanning = false;
            ScanProgress.Visibility = Visibility.Collapsed;
            SearchButton.IsEnabled = true;
            SearchBox.IsEnabled = true;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void UpdateResults(IReadOnlyList<ulong> results)
    {
        _results.Clear();

        if (results.Count <= ResultThreshold)
        {
            MemoryValueType type = _scanner?.ValueType ?? MemoryValueType.DWord;

            foreach (ulong address in results)
            {
                var row = new ResultRow(address, ReadFormatted(type, address), WriteValue);
                row.WriteFailed += message => MessageBox.Show(this, message, "Write Failed",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                _results.Add(row);
            }

            StatusText.Text = $"{results.Count} address(es) found. Edit a value to write it to the process.";
        }
        else
        {
            StatusText.Text = $"{results.Count} address(es) found. Refine the search; the list appears at {ResultThreshold} or fewer.";
        }
    }

    private string ReadFormatted(MemoryValueType type, ulong address)
    {
        int size = MemoryValueTypeInfo.SizeOf(type);
        var buffer = new byte[size];

        if (_memory is not null && _memory.ReadBytes(address, buffer, size, out int read) && read == size)
            return MemoryValueTypeInfo.Format(type, buffer);

        return "??";
    }

    private (bool Ok, string Applied, string? Error) WriteValue(ulong address, string text)
    {
        if (_memory is null || _scanner is null)
            return (false, string.Empty, "No process is open.");

        MemoryValueType type = _scanner.ValueType;
        if (!MemoryValueTypeInfo.TryParse(type, text, out byte[] bytes, out _, out string error))
            return (false, string.Empty, error);

        if (!_memory.WriteBytes(address, bytes))
            return (false, string.Empty, $"Failed to write to 0x{address:X}.");

        return (true, ReadFormatted(type, address), null);
    }

    private void Window_Closing(object sender, CancelEventArgs e)
    {
        _cts?.Cancel();
        _freezeTimer?.Stop();
        _memory?.Dispose();
    }

    private void ResultsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        DependencyObject? source = e.OriginalSource as DependencyObject;
        while (source is not null and not DataGridRow)
            source = VisualTreeHelper.GetParent(source);

        if (source is DataGridRow row)
            row.IsSelected = true;
    }

    private ResultRow? GetSelectedRow()
    {
        if (ResultsGrid.SelectedItem is ResultRow row)
            return row;

        MessageBox.Show(this, "Select an address in the results list first.", "MemSearch",
            MessageBoxButton.OK, MessageBoxImage.Information);
        return null;
    }

    private void BrowseMemory_Click(object sender, RoutedEventArgs e)
    {
        if (_memory is null || _disassembly is null || _assembler is null)
            return;

        ResultRow? row = GetSelectedRow();
        if (row is null)
            return;

        var browser = new CodeBrowserWindow(_memory, _disassembly, _assembler, row.AddressValue, row.AddressValue)
        {
            Owner = this
        };
        browser.Show();
    }

    private void RegisterResult_Click(object sender, RoutedEventArgs e)
    {
        if (_codes is null || _memory is null || _scanner is null)
        {
            MessageBox.Show(this, "Open a process and run a search first.", "Register",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        ResultRow? row = GetSelectedRow();
        if (row is null)
            return;

        CodeEntry entry = _codes.AddData(row.AddressValue, _scanner.ValueType, row.Value, $"0x{row.AddressValue:X}");
        AttachCodeEntry(entry);
        CodesTab.IsSelected = true;
    }

    private void RegisterScript(ulong address, string instruction)
    {
        if (_codes is null)
            return;

        CodeEntry entry = _codes.AddScript(address, instruction, $"script @ 0x{address:X}");
        AttachCodeEntry(entry);
        CodesTab.IsSelected = true;
    }

    private void AttachCodeEntry(CodeEntry entry) => entry.PropertyChanged += CodeEntry_PropertyChanged;

    private void CodeEntry_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not CodeEntry entry || _codes is null)
            return;

        if (e.PropertyName == nameof(CodeEntry.Enabled))
        {
            if (entry.Enabled)
                EnableCodeEntry(entry);
            else
                _codes.Revert(entry);
        }
        else if (e.PropertyName == nameof(CodeEntry.DataType) && entry.Enabled)
        {
            _codes.Revert(entry);
            EnableCodeEntry(entry);
        }
        else if (e.PropertyName == nameof(CodeEntry.Address) && entry.Enabled)
        {
            _codes.Revert(entry);
            EnableCodeEntry(entry);
        }
    }

    private void EnableCodeEntry(CodeEntry entry)
    {
        if (_codes is null)
            return;

        if (_codes.IsAddressActive(entry))
        {
            entry.Enabled = false;
            StatusText.Text = $"0x{entry.AddressValue:X} is already active in another code entry.";
            return;
        }

        if (entry.IsScript && string.IsNullOrWhiteSpace(entry.ScriptText))
            entry.ScriptText = ReadInstructionText(entry.AddressValue);

        if (!_codes.Apply(entry))
        {
            StatusText.Text = entry.LastError ?? "Failed to apply the code entry.";
            entry.Enabled = false;
        }
    }

    private string ReadInstructionText(ulong address)
    {
        if (_memory is null || _disassembly is null)
            return string.Empty;

        List<DisassembledInstruction> list = _disassembly.DecodeForward(_memory, address, 1, 16);
        return list.Count > 0 ? list[0].Text : string.Empty;
    }

    private void RemoveSelectedCode()
    {
        if (_codes is null || CodesGrid.SelectedItem is not CodeEntry entry)
            return;

        entry.PropertyChanged -= CodeEntry_PropertyChanged;
        _codes.Remove(entry);
    }

    private void RemoveCodeButton_Click(object sender, RoutedEventArgs e) => RemoveSelectedCode();

    private void CodesGrid_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Delete)
        {
            e.Handled = true;
            RemoveSelectedCode();
        }
    }

    private void CodesGrid_BeginningEdit(object sender, DataGridBeginningEditEventArgs e)
    {
        if (e.Column == CodeValueColumn && e.Row.Item is CodeEntry { IsScript: true })
            e.Cancel = true;
    }

    private void CodesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (CodesGrid.CurrentColumn != CodeValueColumn)
            return;
        if (CodesGrid.SelectedItem is not CodeEntry { IsScript: true } entry)
            return;

        EditScript(entry);
    }

    private void EditScript_Click(object sender, RoutedEventArgs e)
    {
        if (CodesGrid.SelectedItem is CodeEntry { IsScript: true } entry)
            EditScript(entry);
    }

    private void EditScript(CodeEntry entry)
    {
        if (_memory is null || _disassembly is null || _assembler is null)
            return;

        var editor = new ScriptEditorWindow(_memory, _disassembly, _assembler, entry) { Owner = this };
        if (editor.ShowDialog() != true)
            return;

        if (entry.Enabled && _codes is not null)
        {
            _codes.Revert(entry);
            EnableCodeEntry(entry);
        }
    }

    private void CodesGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        DependencyObject? source = e.OriginalSource as DependencyObject;
        while (source is not null and not DataGridRow)
            source = VisualTreeHelper.GetParent(source);

        if (source is DataGridRow row)
            row.IsSelected = true;
    }

    private void IntervalBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_freezeTimer is null)
            return;

        if (int.TryParse(IntervalBox.Text, out int ms) && ms >= 20 && ms <= 10000)
            _freezeTimer.Interval = TimeSpan.FromMilliseconds(ms);
    }

    private void FindWrites_Click(object sender, RoutedEventArgs e) => TrackAccess(AccessKind.Write);

    private void FindAccesses_Click(object sender, RoutedEventArgs e) => TrackAccess(AccessKind.ReadWrite);

    private void FindExecutes_Click(object sender, RoutedEventArgs e) => TrackAccess(AccessKind.Execute);

    private void TrackAccess(AccessKind mode)
    {
        if (_memory is null || _disassembly is null || _assembler is null)
            return;

        if (!_memory.Is64BitProcess)
        {
            MessageBox.Show(this, "Access tracking is only supported for 64-bit target processes.",
                "MemSearch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ResultRow? row = GetSelectedRow();
        if (row is null)
            return;

        int size = _scanner is not null ? MemoryValueTypeInfo.SizeOf(_scanner.ValueType) : 4;
        AccessMechanism mechanism = _accessMechanism;

        var window = new AccessTrackerWindow(_memory, _disassembly, _assembler, row.AddressValue, mode, size,
            mechanism: mechanism, registerScript: RegisterScript)
        {
            Owner = this
        };
        window.Show();
    }

    private void ProbeAttachOnly_Click(object sender, RoutedEventArgs e) => RunProbe(ProbeMode.AttachOnly);

    private void ProbeExternalDr_Click(object sender, RoutedEventArgs e) => RunProbe(ProbeMode.ExternalDr);

    private void ProbeExternalGuard_Click(object sender, RoutedEventArgs e) => RunProbe(ProbeMode.ExternalGuard);

    private void ProbeDecoyBaseline_Click(object sender, RoutedEventArgs e) => RunProbe(ProbeMode.DecoyBaseline);

    private void ProbeDecoyGuard_Click(object sender, RoutedEventArgs e) => RunProbe(ProbeMode.DecoyGuard);

    private void ProbeDecoyDr_Click(object sender, RoutedEventArgs e) => RunProbe(ProbeMode.DecoyDr);

    private static bool IsDecoy(ProbeMode probeMode) =>
        probeMode is ProbeMode.DecoyBaseline or ProbeMode.DecoyGuard or ProbeMode.DecoyDr;

    private void RunProbe(ProbeMode probeMode)
    {
        if (_memory is null || _disassembly is null || _assembler is null)
            return;

        ulong address = 0;
        if (!IsDecoy(probeMode))
        {
            ResultRow? row = GetSelectedRow();
            if (row is null)
                return;
            address = row.AddressValue;
        }

        int size = _scanner is not null ? MemoryValueTypeInfo.SizeOf(_scanner.ValueType) : 4;
        var window = new AccessTrackerWindow(_memory, _disassembly, _assembler, address, AccessKind.Write, size, probeMode,
            registerScript: RegisterScript)
        {
            Owner = this
        };
        window.Show();
    }

    private void CodeBrowserMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_memory is null || _disassembly is null || _assembler is null)
        {
            MessageBox.Show(this, "Open a process first.", "Code Browser",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var browser = new CodeBrowserWindow(_memory, _disassembly, _assembler, GetDefaultBrowseAddress(), null)
        {
            Owner = this
        };
        browser.Show();
    }

    private ulong GetDefaultBrowseAddress()
    {
        if (ResultsGrid.SelectedItem is ResultRow row)
            return row.AddressValue;

        if (_memory is not null)
        {
            try
            {
                using System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(_memory.ProcessId);
                if (process.MainModule is { } module)
                    return unchecked((ulong)module.BaseAddress.ToInt64());
            }
            catch (Exception)
            {
                // fall through to 0
            }
        }

        return 0;
    }
}
