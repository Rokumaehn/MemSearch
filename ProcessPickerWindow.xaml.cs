using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace OmniHax;

public partial class ProcessPickerWindow : Window
{
    private readonly List<ProcessItem> _allProcesses;

    internal ProcessItem? SelectedProcess { get; private set; }

    public ProcessPickerWindow()
    {
        InitializeComponent();
        _allProcesses = ProcessCatalog.GetProcesses();
        ApplyFilter();

        Loaded += (_, _) =>
        {
            if (ProcessList.Items.Count > 0)
                ProcessList.SelectedIndex = 0;
        };
    }

    private void VisibleOnlyCheck_Changed(object sender, RoutedEventArgs e) => ApplyFilter();

    private void FilterBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void ApplyFilter()
    {
        if (ProcessList is null)
            return;

        bool visibleOnly = VisibleOnlyCheck.IsChecked == true;
        string filter = FilterBox.Text?.Trim() ?? string.Empty;

        IEnumerable<ProcessItem> items = _allProcesses;

        if (visibleOnly)
            items = items.Where(p => p.HasVisibleWindow);

        if (filter.Length > 0)
            items = items.Where(p =>
                p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                p.Id.ToString().Contains(filter, StringComparison.Ordinal));

        ProcessList.ItemsSource = items.OrderBy(p => p.Name).ToList();
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => Accept();

    private void ProcessList_MouseDoubleClick(object sender, MouseButtonEventArgs e) => Accept();

    private void Accept()
    {
        if (ProcessList.SelectedItem is ProcessItem item)
        {
            SelectedProcess = item;
            DialogResult = true;
            return;
        }

        MessageBox.Show(this, "Select a process from the list.", "Open Process",
            MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
