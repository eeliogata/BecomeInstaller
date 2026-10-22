$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This script only runs on Windows.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}

if (-not ('TrustedInstallerLauncher' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class TrustedInstallerLauncher
{
    private const uint TokenAdjustPrivileges = 0x20;
    private const uint ProcessCreateProcess = 0x80;
    private const uint SePrivilegeEnabled = 0x2;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateNewConsole = 0x00000010;
    private static readonly IntPtr ParentProcessAttribute = new IntPtr(0x20000);

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES privileges, uint length, IntPtr previous, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count,
        int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags,
        IntPtr attribute, IntPtr value, IntPtr valueSize, IntPtr previous, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint creationFlags, IntPtr environment, string currentDirectory,
        ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static void EnableDebugPrivilege()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "LookupPrivilegeValue failed");
            TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES();
            privileges.PrivilegeCount = 1;
            privileges.Luid = luid;
            privileges.Attributes = SePrivilegeEnabled;
            bool ok = AdjustTokenPrivileges(token, false, ref privileges, 0,
                IntPtr.Zero, IntPtr.Zero);
            int error = Marshal.GetLastWin32Error();
            if (!ok || error != 0)
                throw new Win32Exception(error, "Could not enable SeDebugPrivilege");
        }
        finally { CloseHandle(token); }
    }

    public static uint Spawn(uint parentPid, string application)
    {
        EnableDebugPrivilege();
        IntPtr parent = OpenProcess(ProcessCreateProcess, false, parentPid);
        if (parent == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");

        IntPtr list = IntPtr.Zero;
        IntPtr parentValue = IntPtr.Zero;
        bool initialized = false;
        try
        {
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Attribute size query failed");
            list = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(list, 1, 0, ref size))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Attribute initialization failed");
            initialized = true;

            parentValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(parentValue, parent);
            if (!UpdateProcThreadAttribute(list, 0, ParentProcessAttribute,
                parentValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Setting parent process failed");

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.lpDesktop = "winsta0\\default";
            startup.lpAttributeList = list;
            PROCESS_INFORMATION child;
            StringBuilder command = new StringBuilder("\"" + application + "\" -NoLogo -NoProfile");
            if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero,
                false, ExtendedStartupInfoPresent | CreateNewConsole, IntPtr.Zero,
                null, ref startup, out child))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed");
            try { return child.dwProcessId; }
            finally
            {
                CloseHandle(child.hThread);
                CloseHandle(child.hProcess);
            }
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(list);
            if (parentValue != IntPtr.Zero) Marshal.FreeHGlobal(parentValue);
            if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
            CloseHandle(parent);
        }
    }
}
'@
}

$service = Get-Service -Name TrustedInstaller
if ($service.Status -eq 'Stopped') {
    Start-Service -Name TrustedInstaller
}
$service.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))

$serviceInfo = Get-CimInstance Win32_Service -Filter "Name='TrustedInstaller'"
if (-not $serviceInfo -or $serviceInfo.ProcessId -eq 0) {
    throw 'Could not find the running TrustedInstaller process.'
}

$shell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$childPid = [TrustedInstallerLauncher]::Spawn([uint32]$serviceInfo.ProcessId, $shell)
Write-Output "Started PowerShell as TrustedInstaller (PID $childPid)."
