$ErrorActionPreference='Stop'
$bash = if ($env:PROBE_BASH) { $env:PROBE_BASH }
        else { "$env:ProgramFiles\Git\usr\bin\bash.exe" }
$probe = Start-Process -FilePath "$PSScriptRoot\inject_probe.exe" `
  -ArgumentList 'thread','C:\Windows\System32\kernel32.dll',
    $bash,
    "$PSScriptRoot\forks.sh" `
  -PassThru -RedirectStandardError "$PSScriptRoot\hang.err" -RedirectStandardOutput "$PSScriptRoot\hang.out" -NoNewWindow
Start-Sleep -Seconds 6
Write-Output "=== process tree under probe pid $($probe.Id) ==="
$all = Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,CreationDate
function Show($pid0,$depth) {
  foreach ($p in $all | Where-Object { $_.ParentProcessId -eq $pid0 }) {
    Write-Output ((' ' * $depth) + "pid=$($p.ProcessId) $($p.Name) :: $($p.CommandLine)")
    Show $p.ProcessId ($depth+2)
  }
}
Show $probe.Id 0
Write-Output "=== all bash/grep processes right now ==="
$all | Where-Object { $_.Name -match 'bash|grep|sh\.exe' } | ForEach-Object {
  Write-Output "pid=$($_.ProcessId) ppid=$($_.ParentProcessId) $($_.Name) created=$($_.CreationDate)"
}
Write-Output "=== threads of the hung bash ==="
foreach ($p in $all | Where-Object { $_.ParentProcessId -eq $probe.Id -and $_.Name -eq 'bash.exe' }) {
  $proc = Get-Process -Id $p.ProcessId
  Write-Output "bash pid=$($p.ProcessId) threads=$($proc.Threads.Count) cpu=$($proc.CPU) handles=$($proc.HandleCount)"
  foreach ($t in $proc.Threads) {
    Write-Output ("  tid=$($t.Id) state=$($t.ThreadState) wait=$($t.WaitReason) start=0x{0:X}" -f $t.StartAddress.ToInt64())
  }
}
Start-Sleep -Seconds 3
Write-Output "=== second sample of hung bash CPU (is it spinning?) ==="
foreach ($p in $all | Where-Object { $_.ParentProcessId -eq $probe.Id -and $_.Name -eq 'bash.exe' }) {
  try { $proc = Get-Process -Id $p.ProcessId; Write-Output "bash pid=$($p.ProcessId) cpu=$($proc.CPU)" } catch { Write-Output "gone" }
}
$probe.WaitForExit(70000) | Out-Null
Write-Output "=== probe stderr ==="
Get-Content "$PSScriptRoot\hang.err"
