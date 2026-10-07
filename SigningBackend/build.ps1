param([string]$Tools = '', [switch]$Test)
$ErrorActionPreference = 'Stop'
$previousCargo = $env:CARGO_HOME
$previousRustup = $env:RUSTUP_HOME
$previousFlags = $env:CARGO_ENCODED_RUSTFLAGS
$previousPath = $env:PATH
$previousCompiler = $env:CC
try {
    $cargo = 'cargo'
    if ($Tools) {
        $Tools = [IO.Path]::GetFullPath($Tools)
        $env:CARGO_HOME = Join-Path $Tools 'cargo'
        $env:RUSTUP_HOME = Join-Path $Tools 'rustup'
        $compiler = Join-Path $Tools 'llvm-mingw-20260616-msvcrt-x86_64/bin/x86_64-w64-mingw32-gcc.exe'
        $env:PATH = (Split-Path $compiler) + ';' + $env:PATH
        $env:CC = $compiler
        $env:CARGO_ENCODED_RUSTFLAGS = @('-C', 'link-self-contained=yes', '-C', "linker=$compiler") -join [char]31
        $cargo = Join-Path $env:CARGO_HOME 'bin/cargo.exe'
    }
    $command = if ($Test) { 'test' } else { 'build' }
    & $cargo $command --locked --release --manifest-path "$PSScriptRoot/Cargo.toml"
    if ($LASTEXITCODE -ne 0) { throw 'Custody signer build failed' }
} finally {
    $env:CARGO_HOME = $previousCargo
    $env:RUSTUP_HOME = $previousRustup
    $env:CARGO_ENCODED_RUSTFLAGS = $previousFlags
    $env:PATH = $previousPath
    $env:CC = $previousCompiler
}
