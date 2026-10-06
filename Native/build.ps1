param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$compiler = Join-Path $PSScriptRoot 'tools/zig-windows-x86_64-0.13.0/zig.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    throw 'Run Native/setup.ps1 once to download the local C compiler'
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'build' }
$buildDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $buildDirectory | Out-Null
$vendor = Join-Path $PSScriptRoot 'vendor/monero'
$savedGlobalCache = $env:ZIG_GLOBAL_CACHE_DIR
$savedLocalCache = $env:ZIG_LOCAL_CACHE_DIR
try {
    $env:ZIG_GLOBAL_CACHE_DIR = Join-Path $PSScriptRoot 'cache/global'
    $env:ZIG_LOCAL_CACHE_DIR = Join-Path $PSScriptRoot 'cache/local'
    $arguments = @(
        'cc', '-target', 'x86_64-windows-gnu', '-std=c11', '-O2',
        '-fno-strict-aliasing', '-fwrapv', '-shared', '-I', $vendor,
        '-I', (Join-Path $PSScriptRoot 'compat'),
        (Join-Path $PSScriptRoot 'xtop_monero.c'),
        (Join-Path $PSScriptRoot 'xtop_proofs.c'),
        (Join-Path $vendor 'crypto-ops.c'),
        (Join-Path $vendor 'crypto-ops-data.c'),
        (Join-Path $vendor 'hash.c'),
        (Join-Path $vendor 'keccak.c'),
        '-o', (Join-Path $buildDirectory 'xtop_monero.dll')
    )
    & $compiler @arguments
    if ($LASTEXITCODE -ne 0) { throw "Native build failed with exit code $LASTEXITCODE." }
    Write-Output 'Built xtop_monero.dll (Monero v0.18.5.1 output primitives).'
}
finally {
    $env:ZIG_GLOBAL_CACHE_DIR = $savedGlobalCache
    $env:ZIG_LOCAL_CACHE_DIR = $savedLocalCache
}
