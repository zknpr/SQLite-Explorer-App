# Run in an interactive Windows QA desktop against an installed application.
# Sends session messages only to the process started here; does not log off Windows.
param(
    [Parameter(Mandatory=$true)][string]$Application,
    [Parameter(Mandatory=$true)][string]$Database,
    [Parameter(Mandatory=$true)][string]$Evidence,
    [ValidateSet('shutdown', 'logoff', 'restart-manager')][string]$Kind = 'logoff',
    [ValidateSet('visible', 'event-loop')][string]$Target = 'visible'
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Evidence) { throw 'Use a new evidence directory' }
$null = New-Item -ItemType Directory -Path $Evidence
$Evidence = (Resolve-Path -LiteralPath $Evidence).Path
$fixture = Join-Path $Evidence 'session fixture.sqlite'
Copy-Item -LiteralPath $Database -Destination $fixture
$before = (Get-FileHash -LiteralPath $fixture).Hash
$flags = switch ($Kind) {
    'shutdown' { [long]0 }
    'logoff' { [long]2147483648 }
    'restart-manager' { [long]1 }
}
if (-not ('SessionSmoke' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class SessionSmoke {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeoutW(IntPtr hwnd, uint message,
        UIntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);
    delegate bool EnumProc(IntPtr hwnd, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr data);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int capacity);
    public static IntPtr EventLoopWindow(uint pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, unused) => {
            uint owner; GetWindowThreadProcessId(hwnd, out owner);
            var name = new StringBuilder(256); GetClassNameW(hwnd, name, name.Capacity);
            if (owner == pid && name.ToString() == "Tao Thread Event Target") { found = hwnd; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@
}
$app = $null
$children = @()
try {
    $app = Start-Process -FilePath $Application -ArgumentList ('"' + $fixture + '"') -PassThru `
        -RedirectStandardOutput (Join-Path $Evidence 'app.stdout.log') `
        -RedirectStandardError (Join-Path $Evidence 'app.stderr.log')
    # Hold the process handle so ExitCode remains available after the process exits.
    $null = $app.Handle
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 200
        $app.Refresh()
        if ($app.HasExited) { throw 'App exited before opening the fixture' }
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($app.Id) AND Name='tjs.exe'")
    } until (($app.MainWindowHandle -ne 0 -and $children.Count -gt 0) -or [DateTime]::UtcNow -gt $deadline)
    if ($app.MainWindowHandle -eq 0 -or $children.Count -eq 0) { throw 'Native app/sidecar did not start' }
    $window = $app.MainWindowHandle
    if ($Target -eq 'event-loop') {
        $window = [SessionSmoke]::EventLoopWindow($app.Id)
        if ($window -eq [IntPtr]::Zero) { throw 'Tao event-loop window not found' }
    }
    [UIntPtr]$reply = [UIntPtr]::Zero
    $sent = [SessionSmoke]::SendMessageTimeoutW($window, 0x11, [UIntPtr]::Zero, [IntPtr]$flags, 2, 5000, [ref]$reply)
    if ($sent -eq [IntPtr]::Zero -or $reply.ToUInt64() -ne 1) { throw 'Clean session query was not accepted' }
    $sent = [SessionSmoke]::SendMessageTimeoutW($window, 0x16, [UIntPtr]::Zero, [IntPtr]$flags, 2, 5000, [ref]$reply)
    if ($sent -eq [IntPtr]::Zero) { throw 'Cancelled session-end message failed' }
    Start-Sleep -Milliseconds 500
    if ($app.HasExited) { throw 'Cancelled session end closed the app' }
    foreach ($child in $children) {
        if (-not (Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue)) { throw 'Cancellation killed a sidecar' }
    }
    # A committed session end must exit itself, including when sent by Restart Manager.
    # The HWND may disappear before SendMessageTimeout returns; observe the process.
    $null = [SessionSmoke]::SendMessageTimeoutW($window, 0x16, [UIntPtr]::new([uint32]1), [IntPtr]$flags, 2, 10000, [ref]$reply)
    if (-not $app.WaitForExit(10000)) { throw 'Committed session end did not exit the app' }
    $stderr = Get-Content -LiteralPath (Join-Path $Evidence 'app.stderr.log') -Raw
    if ($stderr -match 'panicked|cannot move state from Destroyed') { throw 'Session teardown panicked' }
    if ($app.ExitCode -ne 0) { throw "Session teardown exit code: $($app.ExitCode)" }
    foreach ($child in $children) {
        if (Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue) { throw 'Session end left a sidecar alive' }
    }
    if ($stderr -notmatch 'sidecar shut down: exit code 0') { throw 'Missing orderly sidecar shutdown evidence' }
    if ((Get-FileHash -LiteralPath $fixture).Hash -ne $before) { throw 'Session messages modified the database' }
    @{kind=$Kind; target=$Target; cancelledSessionPreserved=$true; committedExitCode=$app.ExitCode;
      sidecarsReaped=$children.Count; databaseUnchanged=$true} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'result.json')
    Write-Output "PASS $Kind / $Target cancellation and committed session teardown"
} finally {
    # Only this disposable test instance and its captured sidecars are eligible.
    if ($null -ne $app -and -not $app.HasExited) { Stop-Process -Id $app.Id -Force }
    foreach ($child in $children) {
        if (Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue) { Stop-Process -Id $child.ProcessId -Force }
    }
}
