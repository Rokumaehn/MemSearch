using System.Diagnostics;
using System.Text;

namespace MemSearch;

internal sealed class ProcessItem
{
    public int Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public bool HasVisibleWindow { get; init; }
}

internal static class ProcessCatalog
{
    public static List<ProcessItem> GetProcesses()
    {
        Dictionary<int, string> visibleWindows = GetVisibleWindowTitles();
        var result = new List<ProcessItem>();

        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                int id = process.Id;
                bool hasVisibleWindow = visibleWindows.TryGetValue(id, out string? title);

                result.Add(new ProcessItem
                {
                    Id = id,
                    Name = process.ProcessName,
                    Title = title ?? string.Empty,
                    HasVisibleWindow = hasVisibleWindow
                });
            }
            catch (Exception)
            {
                // Process may exit or deny access while enumerating.
            }
            finally
            {
                process.Dispose();
            }
        }

        return result;
    }

    private static Dictionary<int, string> GetVisibleWindowTitles()
    {
        var map = new Dictionary<int, string>();

        NativeMethods.EnumWindows((hWnd, _) =>
        {
            if (!NativeMethods.IsWindowVisible(hWnd))
                return true;

            NativeMethods.GetWindowThreadProcessId(hWnd, out uint pid);
            if (pid == 0)
                return true;

            string title = string.Empty;
            int length = NativeMethods.GetWindowTextLength(hWnd);
            if (length > 0)
            {
                var builder = new StringBuilder(length + 1);
                if (NativeMethods.GetWindowText(hWnd, builder, builder.Capacity) > 0)
                    title = builder.ToString();
            }

            int key = unchecked((int)pid);
            if (!map.TryGetValue(key, out string? existing) || (existing.Length == 0 && title.Length > 0))
                map[key] = title;

            return true;
        }, IntPtr.Zero);

        return map;
    }
}
