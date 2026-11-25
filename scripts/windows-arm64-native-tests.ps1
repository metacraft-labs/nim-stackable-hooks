# Build and run the Windows on Arm tests NATIVELY on an ARM64 Windows host.
#
# Why this lane exists: `ci-reprobuild.yml`'s windows-arm64 leg sets
# `WINDOWS_DIY_ARCH_OVERRIDE: x64`, so everything it builds is x64 and runs
# under emulation, and the `when defined(windows) and defined(arm64)` bodies of
# the ARM64 backend's tests are compiled out there. reprobuild-pm
# spec/Distribution-And-Packaging.md section 7.1 rejects x64 emulation as
# arm64 coverage (W1(c), W8), and spec/Monitor-Hook-Shim.md "Windows on Arm64
# install backend" is only qualified by native ARM64 runs. This script is that
# run, until a native Nim prefix exists (reprobuild-pm milestone WA-M4) and the
# reprobuild leg can drop its override.
#
# Toolchain:
# * C: llvm-mingw, aarch64-hosted, UCRT, at the release and sha256 reprobuild
#   pins for its own windows-aarch64 leg (`windows/toolchain-versions.env`,
#   `LLVM_MINGW_WIN_ARM64_*`). It runs natively and targets both ARM64 and x64.
# * Nim: the official x64 prefix (`NIM_WIN_X64_SHA256` there). Until WA-M4 it
#   is the only pinned Windows Nim, so it runs emulated -- as a code generator
#   only, exactly the bootstrap section 7.1 measured for the Nim seed. Every
#   test image it produces is checked to be of the requested machine before it
#   runs, so nothing that is tested runs emulated except the one test whose
#   subject IS an x64 process on Windows on Arm (the x64 build of
#   test_windows_root_machine_gate, reprobuild-pm issue 2026-11-20).
#
# Exit code: 0 when every test passed; otherwise it throws, naming each
# failed test.
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $WorkRoot,
  [Parameter(Mandatory)] [string] $NimVersion,
  [Parameter(Mandatory)] [string] $NimSha256,
  [Parameter(Mandatory)] [string] $LlvmMingwRelease,
  [Parameter(Mandatory)] [string] $LlvmMingwSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# IMAGE_FILE_MACHINE_* values:
# https://learn.microsoft.com/windows/win32/sysinfo/image-file-machine-constants
$Machines = @{ arm64 = 0xAA64; amd64 = 0x8664 }

function Get-PeMachine([string] $Path) {
  # e_lfanew at 0x3C, then 'PE\0\0', then the COFF Machine field.
  # https://learn.microsoft.com/windows/win32/debug/pe-format
  $bytes = [IO.File]::ReadAllBytes($Path)
  if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    throw "$Path is not a PE image"
  }
  $lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
  if ($lfanew -lt 0x40 -or $lfanew + 6 -gt $bytes.Length -or
      [BitConverter]::ToUInt32($bytes, $lfanew) -ne 0x00004550) {
    throw "$Path has no PE header"
  }
  [BitConverter]::ToUInt16($bytes, $lfanew + 4)
}

function Get-Pinned([string] $Url, [string] $Sha256, [string] $Destination) {
  # Download once and refuse anything whose digest is not the pinned one.
  Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash
  if ($actual -ne $Sha256.ToUpperInvariant()) {
    throw "sha256 mismatch for $Url`: expected $Sha256, got $actual"
  }
}

$native = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture
# Win32_Processor.Architecture 12 = ARM64.
if ($native -ne 12) {
  throw "this lane must run on a native ARM64 Windows host (Win32_Processor.Architecture=$native)"
}

New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# --- llvm-mingw (native) ------------------------------------------------------
$llvmName = "llvm-mingw-$LlvmMingwRelease-ucrt-aarch64"
$llvmZip = Join-Path $WorkRoot "$llvmName.zip"
Get-Pinned "https://github.com/mstorsjo/llvm-mingw/releases/download/$LlvmMingwRelease/$llvmName.zip" `
  $LlvmMingwSha256 $llvmZip
Expand-Archive -LiteralPath $llvmZip -DestinationPath $WorkRoot -Force
$llvmBin = Join-Path $WorkRoot "$llvmName/bin"
if ((Get-PeMachine (Join-Path $llvmBin 'clang.exe')) -ne $Machines.arm64) {
  throw "llvm-mingw's clang.exe is not an ARM64 image"
}
$drivers = @{
  arm64 = Join-Path $llvmBin 'aarch64-w64-mingw32-gcc.exe'
  amd64 = Join-Path $llvmBin 'x86_64-w64-mingw32-gcc.exe'
}
foreach ($d in $drivers.Values) {
  if (-not (Test-Path -LiteralPath $d -PathType Leaf)) { throw "llvm-mingw has no $d" }
}

# --- Nim (code generator) -----------------------------------------------------
$nimZip = Join-Path $WorkRoot "nim-${NimVersion}_x64.zip"
Get-Pinned "https://nim-lang.org/download/nim-${NimVersion}_x64.zip" $NimSha256 $nimZip
Expand-Archive -LiteralPath $nimZip -DestinationPath $WorkRoot -Force
$nimBin = Join-Path $WorkRoot "nim-$NimVersion/bin"
$env:PATH = "$llvmBin;$nimBin;$env:PATH"

# Every `nim c` in this job -- including the fixture builds the tests run
# themselves with `--cpu:<their own CPU>` -- must reach llvm-mingw's driver
# for that CPU. Nim reads `<cpu>.<os>.gcc.exe` from its user configuration,
# `%APPDATA%\nim\nim.cfg`, but ONLY for a cross build: this nim.exe is x64,
# so `--cpu:amd64` is its native target and uses the bare `gcc.exe` key,
# which would otherwise find llvm-mingw's plain `gcc.exe` (an ARM64 driver;
# measured, run 45593083238). Both spellings are therefore set. This host is
# ephemeral, so the file lives and dies with the job.
$nimCfgDir = Join-Path $env:APPDATA 'nim'
New-Item -ItemType Directory -Force $nimCfgDir | Out-Null
@(
  "gcc.exe = `"$($drivers.amd64 -replace '\\', '/')`""
  "gcc.linkerexe = `"$($drivers.amd64 -replace '\\', '/')`""
  "arm64.windows.gcc.exe = `"$($drivers.arm64 -replace '\\', '/')`""
  "arm64.windows.gcc.linkerexe = `"$($drivers.arm64 -replace '\\', '/')`""
  "amd64.windows.gcc.exe = `"$($drivers.amd64 -replace '\\', '/')`""
  "amd64.windows.gcc.linkerexe = `"$($drivers.amd64 -replace '\\', '/')`""
) | Set-Content -LiteralPath (Join-Path $nimCfgDir 'nim.cfg') -Encoding ascii

& nim -v
if ($LASTEXITCODE -ne 0) { throw "nim -v failed" }

# --- the tests ----------------------------------------------------------------
# arm64: every test whose body is live on native Windows ARM64.
# amd64: the root machine gate's issue case, an x64 engine on Windows on Arm.
$plan = @(
  @{ cpu = 'arm64'; tests = @(
      'test_a64_relocate',
      'test_windows_machine',
      'test_windows_env_block',
      'test_windows_arm64_inline_hook',
      'test_windows_arm64_entry_park',
      'test_windows_root_machine_gate',
      'test_windows_child_machine_gate',
      'test_windows_injector_capture',
      'test_windows_injector_job') },
  @{ cpu = 'amd64'; tests = @(
      'test_windows_machine',
      'test_windows_root_machine_gate',
      'test_windows_child_machine_gate') }
)

$failed = @()
foreach ($group in $plan) {
  $cpu = $group.cpu
  $outDir = Join-Path 'build/test-bin' "windows-$cpu"
  New-Item -ItemType Directory -Force $outDir | Out-Null
  foreach ($t in $group.tests) {
    Write-Host "=== $t ($cpu)"
    $exe = Join-Path $outDir "$t.exe"
    & nim c --cpu:$cpu --hints:off --path:src `
      "--nimcache:.nimcache/windows-$cpu/$t" "--out:$exe" "tests/$t.nim"
    if ($LASTEXITCODE -ne 0) { $failed += "$t/$cpu (build exit $LASTEXITCODE)"; continue }
    $machine = Get-PeMachine $exe
    if ($machine -ne $Machines[$cpu]) {
      $failed += "$t/$cpu (image machine 0x$('{0:X4}' -f $machine), not $cpu)"
      continue
    }
    if ($cpu -eq 'amd64') {
      # The x64 build of the root machine gate test needs a pure ARM64 child:
      # the ARM64 build of the same test, run in its `--exit-with` mode. The
      # arm64 group runs first, so it exists by now.
      $env:STACKABLE_HOOKS_NATIVE_ARM64_CHILD = (Resolve-Path (Join-Path 'build/test-bin/windows-arm64' 'test_windows_root_machine_gate.exe')).Path
    }
    & $exe
    if ($LASTEXITCODE -ne 0) { $failed += "$t/$cpu (exit $LASTEXITCODE)" }
  }
}
if ($failed.Count -gt 0) { throw "failed: $($failed -join '; ')" }
Write-Host "all native Windows on Arm tests passed"
