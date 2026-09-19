namespace OmniHax;

internal static class Privileges
{
    private static int _attempted;

    /// <summary>
    /// Enables SeDebugPrivilege for the current process so protected targets can
    /// be opened and debugged. Safe to call repeatedly.
    /// </summary>
    public static void EnableDebugPrivilege()
    {
        if (Interlocked.Exchange(ref _attempted, 1) != 0)
            return;

        if (!NativeMethods.OpenProcessToken(
                NativeMethods.GetCurrentProcess(),
                NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY,
                out IntPtr token))
        {
            return;
        }

        try
        {
            if (!NativeMethods.LookupPrivilegeValue(null, "SeDebugPrivilege", out NativeMethods.LUID luid))
                return;

            var privileges = new NativeMethods.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new NativeMethods.LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = NativeMethods.SE_PRIVILEGE_ENABLED
                }
            };

            NativeMethods.AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
    }
}
