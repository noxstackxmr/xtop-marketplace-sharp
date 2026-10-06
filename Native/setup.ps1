$ErrorActionPreference = 'Stop'
$toolDirectory = Join-Path $PSScriptRoot 'tools'
$archive = Join-Path $toolDirectory 'zig-0.13.0.zip'
$compiler = Join-Path $toolDirectory 'zig-windows-x86_64-0.13.0/zig.exe'
$expectedHash = 'd859994725ef9402381e557c60bb57497215682e355204d754ee3df75ee3c158'
New-Item -ItemType Directory -Force -Path $toolDirectory | Out-Null
if (-not (Test-Path -LiteralPath $archive)) {
    & curl.exe -sS -L --fail --max-time 300 `
        'https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip' `
        -o $archive
    if ($LASTEXITCODE -ne 0) { throw 'Zig download failed.' }
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'Zig archive checksum mismatch. No files have been extracted or executed.'
}
if (-not (Test-Path -LiteralPath $compiler)) {
    Expand-Archive -LiteralPath $archive -DestinationPath $toolDirectory -Force
}
Write-Output 'Local Zig compiler is ready. No system settings were changed.'
