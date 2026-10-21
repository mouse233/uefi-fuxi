#requires -Version 7.0
<#
Collect private fuxi boot evidence after explicit permission for root reads.
No reboot, fastboot, partition write or phone-side temporary file is used.
Keep the output private: images, cmdline, FDT and logs may contain identifiers.
#>
param(
    [string]$Adb = 'adb',
    [string]$OutputParent = '.',
    [ValidateSet('a','b')][string]$ExpectedSlot = 'b',
    [switch]$AllowRootReads
)
$ErrorActionPreference = 'Stop'
if (-not $AllowRootReads) { throw 'Explicit permission for this root-read session is required; pass -AllowRootReads only after obtaining it.' }
$Adb = (Get-Command $Adb -CommandType Application -ErrorAction Stop).Source
$deviceLines = @(& $Adb devices -l | Where-Object { $_ -match '^\S+\s+device\s' })
if ($deviceLines.Count -ne 1) { throw 'Exactly one authorized ADB device is required.' }
$transportMatch = [regex]::Match($deviceLines[0], 'transport_id:(\d+)')
if (-not $transportMatch.Success) { throw 'ADB did not report a transport ID; update platform-tools.' }
$transport = $transportMatch.Groups[1].Value
$slot = (& $Adb -t $transport shell getprop ro.boot.slot_suffix | Out-String).Trim()
$model = (& $Adb -t $transport shell getprop ro.product.device | Out-String).Trim()
if ($slot -ne ('_' + $ExpectedSlot) -or $model -ne 'fuxi') { throw 'Device or slot differs from the expected fuxi session; stop and review.' }
# These Android properties are routing guards, not independent hardware or unlock proof.
$OutputParent = (Resolve-Path -LiteralPath $OutputParent -ErrorAction Stop).Path
$captureDirectory = Join-Path $OutputParent ('fuxi-readonly-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
[void](New-Item -ItemType Directory -Path $captureDirectory)
$receipts = [System.Collections.Generic.List[object]]::new()
function Save-RootRead([string]$FileName, [string]$ReadCommand) {
    $target = Join-Path $captureDirectory $FileName
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Adb
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($argument in @('-t', $transport, 'exec-out', 'su', '-c', $ReadCommand)) { $psi.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $started = [DateTime]::UtcNow.ToString('o')
    [void]$process.Start()
    $stream = [IO.File]::Create($target)
    try {
        $copyTask = $process.StandardOutput.BaseStream.CopyToAsync($stream)
        $errorTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(90000)) { $process.Kill(); throw 'ADB read timed out.' }
        [void]$copyTask.GetAwaiter().GetResult()
        $stderr = $errorTask.GetAwaiter().GetResult()
    } finally { $stream.Dispose() }
    $receipt = [ordered]@{ file=$FileName; command=$ReadCommand; started_utc=$started; exit_code=$process.ExitCode; bytes=(Get-Item -LiteralPath $target).Length; sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant(); stderr=$stderr }
    $receipts.Add($receipt)
    $receipts | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $captureDirectory 'receipts.json') -Encoding utf8
    Write-Output ('{0}: exit={1}, bytes={2}, sha256={3}' -f $FileName,$receipt.exit_code,$receipt.bytes,$receipt.sha256)
    if ($receipt.exit_code -ne 0) { throw ('Read failed: ' + $FileName) }
}
# Every phone command below reads existing data and writes only its stdout.
# Binary output is copied from BaseStream to avoid PowerShell text conversion.
foreach ($kind in @('boot','vendor_boot','init_boot','dtbo')) {
    $partition = $kind + '_' + $ExpectedSlot
    Save-RootRead ($partition + '.img') ('cat /dev/block/by-name/' + $partition)
}
Save-RootRead 'live-fdt.dtb' 'cat /sys/firmware/fdt'
Save-RootRead 'iomem.txt' 'cat /proc/iomem'
Save-RootRead 'cmdline.txt' 'cat /proc/cmdline'
Save-RootRead 'bootconfig.txt' 'cat /proc/bootconfig'
Save-RootRead 'dmesg.txt' 'dmesg'
Save-RootRead 'pstore-list.txt' 'ls -l /sys/fs/pstore'
# No slot is changed. Fail rather than silently mixing captures across a reboot.
$endSlot = (& $Adb -t $transport shell getprop ro.boot.slot_suffix | Out-String).Trim()
if ($endSlot -ne $slot) { throw 'Slot changed during capture; do not treat the set as a coherent snapshot.' }
Write-Output ('Capture directory: ' + $captureDirectory)
