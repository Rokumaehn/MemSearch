using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Input;

namespace MemSearch;

public partial class MainWindow : Window
{
    private const int ResultThreshold = 100;

    private readonly ObservableCollection<ResultRow> _results = new();
    private readonly object _scanLock = new();

    private ProcessMemory? _memory;
    private MemoryScanner? _scanner;
    private CancellationTokenSource? _cts;
    private bool _typeLocked;
    private bool _isScanning;

    public MainWindow()
    {
        InitializeComponent();

        ResultsGrid.ItemsSource = _results;

        TypeCombo.ItemsSource = MemoryValueTypeInfo.Options;
        TypeCombo.DisplayMemberPath = nameof(ValueTypeOption.DisplayName);
        TypeCombo.SelectedValuePath = nameof(ValueTypeOption.Type);
        TypeCombo.SelectedValue = MemoryValueType.DWord;
    }

    private void OpenProcessButton_Click(object sender, RoutedEventArgs e)
    {
        var picker = new ProcessPickerWindow { Owner = this };
        if (picker.ShowDialog() == true && picker.SelectedProcess is ProcessItem item)
            AttachProcess(item);
    }

    private void AttachProcess(ProcessItem item)
    {
        try
        {
            _memory?.Dispose();
            _memory = ProcessMemory.Open(item.Id, item.Name);
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
        _memory?.Dispose();
    }
}
