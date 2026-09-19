using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace OmniHax;

public partial class AccessTrackerWindow : Window
{
    private const int MaxLogChars = 300_000;

    private readonly ProcessMemory _memory;
    private readonly DisassemblyService _disassembly;
    private readonly AssemblerService _assembler;
    private readonly ulong _address;
    private readonly AccessKind _mode;
    private readonly int _size;
    private readonly ProbeMode _probeMode;
    private readonly AccessMechanism _mechanism;
    private readonly Action<ulong, string>? _registerScript;
    private readonly ObservableCollection<AccessHit> _items = new();

    private IAccessTracker? _tracker;
    private DispatcherTimer? _timer;

    internal AccessTrackerWindow(ProcessMemory memory, DisassemblyService disassembly, AssemblerService assembler,
        ulong address, AccessKind mode, int size, ProbeMode probeMode = ProbeMode.Normal,
        AccessMechanism mechanism = AccessMechanism.HardwareBreakpoints,
        Action<ulong, string>? registerScript = null)
    {
        InitializeComponent();

        _memory = memory;
        _disassembly = disassembly;
        _assembler = assembler;
        _address = address;
        _mode = mode;
        _size = size;
        _probeMode = probeMode;
        _mechanism = mechanism;
        _registerScript = registerScript;

        HitsGrid.ItemsSource = _items;

        WatchSizeCombo.ItemsSource = new[] { 1, 2, 4, 8 };
        WatchSizeCombo.SelectedItem = _size is 1 or 2 or 4 or 8 ? _size : 4;

        HeaderText.Text = probeMode switch
        {
            ProbeMode.AttachOnly =>
                $"DIAGNOSTIC: attaching to {memory.ProcessName} (PID {memory.ProcessId}) without setting any breakpoints, watching 0x{address:X}.",
            ProbeMode.ExternalDr =>
                $"DIAGNOSTIC: setting an external hardware breakpoint on 0x{address:X} in {memory.ProcessName} (PID {memory.ProcessId}) without a debugger.",
            ProbeMode.ExternalGuard =>
                $"DIAGNOSTIC: setting PAGE_GUARD on the page containing 0x{address:X} in {memory.ProcessName} (PID {memory.ProcessId}) without a debugger.",
            ProbeMode.DecoyBaseline =>
                $"DIAGNOSTIC: decoy baseline - allocating an untouched page in {memory.ProcessName} (PID {memory.ProcessId}) (control).",
            ProbeMode.DecoyGuard =>
                $"DIAGNOSTIC: decoy page-guard - guarding an untouched allocated page in {memory.ProcessName} (PID {memory.ProcessId}).",
            ProbeMode.DecoyDr =>
                $"DIAGNOSTIC: decoy hardware breakpoint - arming an untouched allocated page in {memory.ProcessName} (PID {memory.ProcessId}).",
            _ => BuildNormalHeader(memory, mode, address)
        };
    }

    private static string BuildNormalHeader(ProcessMemory memory, AccessKind mode, ulong address)
    {
        string modeText = mode switch
        {
            AccessKind.Write => "writes to",
            AccessKind.Execute => "executes",
            _ => "accesses (read/write)"
        };
        return $"Tracking code that {modeText} 0x{address:X} in {memory.ProcessName} (PID {memory.ProcessId}).";
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        StartTracking();
    }

    private void StartTracking()
    {
        try
        {
            int watchSize = WatchSizeCombo.SelectedItem is int ws ? ws : _size;

            _tracker = _probeMode switch
            {
                ProbeMode.AttachOnly => new HardwareBreakpointTracker(_memory, _disassembly, _address, _mode, watchSize, setBreakpoints: false),
                ProbeMode.ExternalDr => new ExternalBreakpointProbe(_memory, _address, _size),
                ProbeMode.ExternalGuard => new ExternalGuardProbe(_memory, _address, _size),
                ProbeMode.DecoyBaseline => new DecoyProbe(_memory, DecoyKind.Baseline),
                ProbeMode.DecoyGuard => new DecoyProbe(_memory, DecoyKind.Guard),
                ProbeMode.DecoyDr => new DecoyProbe(_memory, DecoyKind.Dr),
                _ when _mechanism == AccessMechanism.InProcessVeh =>
                    new InProcessBreakpointTracker(_memory, _disassembly, _address, watchSize, _mode),
                _ => new HardwareBreakpointTracker(_memory, _disassembly, _address, _mode, watchSize, mechanism: _mechanism)
            };

            _tracker.Start();

            if (!_tracker.IsAligned)
                HeaderText.Text += $"  Watch point aligned down to 0x{_tracker.WatchedAddress:X} ({_tracker.WatchedSize} bytes).";

            if (_probeMode == ProbeMode.Normal)
                HeaderText.Text += _mechanism switch
                {
                    AccessMechanism.GuardPage => "  Using a page-guard watch (no debug registers).",
                    AccessMechanism.InProcessVeh => "  Using an in-process VEH (no debugger, no debug port).",
                    _ => "  Using hardware breakpoints (debug registers)."
                };

            if (_probeMode == ProbeMode.Normal && _mechanism == AccessMechanism.GuardPage && _mode == AccessKind.Execute)
                HeaderText.Text += "  Execute via page-guard is page-granular: it records the first execution of the watched instruction, then stops.";

            _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _timer.Tick += (_, _) => RefreshHits();
            _timer.Start();

            AppendLog($"watching 0x{_tracker.WatchedAddress:X} size={_tracker.WatchedSize} mode={_mode} probe={_probeMode}");
        }
        catch (Exception ex)
        {
            HeaderText.Text = ex.Message;
            StopButton.IsEnabled = false;
            AppendLog($"failed to start tracking: {ex}");
        }
    }

    private void RefreshHits()
    {
        if (_tracker is null)
            return;

        DrainTrackerLog();

        foreach (AccessHit hit in _tracker.GetHits())
        {
            AccessHit? existing = _items.FirstOrDefault(i => i.InstructionAddress == hit.InstructionAddress);
            if (existing is null)
            {
                _items.Add(hit);
            }
            else
            {
                existing.Count = hit.Count;
                existing.Disassembly = hit.Disassembly;
            }
        }

        if (_tracker is { IsRunning: false } && _timer is not null)
        {
            _timer.Stop();
            DrainTrackerLog();
            HeaderText.Text = "Tracking stopped (the target process exited or was detached).";
            return;
        }

        if (_tracker.IsRunning &&
            int.TryParse(AutoStopBox.Text, out int limit) && limit > 0 && _items.Count >= limit)
        {
            StopTracking();
            HeaderText.Text = $"Stopped automatically: reached {limit} distinct writer(s).";
        }
    }

    private void DrainTrackerLog()
    {
        if (_tracker is null)
            return;

        foreach (string line in _tracker.DrainLog())
            AppendLog(line);
    }

    private void AppendLog(string line)
    {
        DiagnosticsBox.AppendText(line + Environment.NewLine);

        if (DiagnosticsBox.Text.Length > MaxLogChars)
            DiagnosticsBox.Text = DiagnosticsBox.Text[^MaxLogChars..];

        DiagnosticsBox.ScrollToEnd();
    }

    private void CopyLog_Click(object sender, RoutedEventArgs e)
    {
        if (DiagnosticsBox.Text.Length == 0)
            return;

        try
        {
            Clipboard.SetText(DiagnosticsBox.Text);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Copy Log", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void SaveLog_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save diagnostics",
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            FileName = $"omnihax-access-{_memory.ProcessId}.txt"
        };

        if (dialog.ShowDialog(this) != true)
            return;

        try
        {
            File.WriteAllText(dialog.FileName, DiagnosticsBox.Text);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save Log", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void HitsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (HitsGrid.SelectedItem is not AccessHit hit)
            return;

        var browser = new CodeBrowserWindow(_memory, _disassembly, _assembler, hit.InstructionAddress, _address)
        {
            Owner = this
        };
        browser.Show();
    }

    private void HitsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        DependencyObject? source = e.OriginalSource as DependencyObject;
        while (source is not null and not DataGridRow)
            source = VisualTreeHelper.GetParent(source);

        if (source is DataGridRow row)
            row.IsSelected = true;
    }

    private void RegisterHit_Click(object sender, RoutedEventArgs e)
    {
        if (HitsGrid.SelectedItem is not AccessHit hit)
        {
            MessageBox.Show(this, "Select an instruction first.", "Register",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _registerScript?.Invoke(hit.InstructionAddress, hit.Disassembly);
    }

    private void StopButton_Click(object sender, RoutedEventArgs e) => StopTracking();

    private void StopTracking()
    {
        _timer?.Stop();
        _tracker?.Stop();
        DrainTrackerLog();
        StopButton.IsEnabled = false;
        HeaderText.Text = "Tracking stopped.";
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        _tracker?.ClearHits();
        _items.Clear();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closing(object sender, CancelEventArgs e)
    {
        _timer?.Stop();
        _tracker?.Dispose();
        DrainTrackerLog();
        _tracker = null;
    }
}
