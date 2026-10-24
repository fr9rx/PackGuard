param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$XzVersion = '5.8.3'
$XzSha256 = '3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0'
$Target = 'x86_64-windows-gnu'

$Root = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root 'build'
$Work = Join-Path $Build 'windows'
$XzPrefix = Join-Path $Work "xz-$XzVersion-install"
$LibLzma = Join-Path $XzPrefix 'lib\liblzma.a'
$Exe = Join-Path $Build 'packguard.exe'

function Require-Tool([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name was not found on PATH; install it first (winget install zig.zig / Kitware.CMake)"
    }
}

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe failed with exit code $LASTEXITCODE"
    }
}

function Build-LibLzma {
    $tarball = Join-Path $Work "xz-$XzVersion.tar.gz"
    if (-not (Test-Path $tarball)) {
        $url = "https://github.com/tukaani-project/xz/releases/download/v$XzVersion/xz-$XzVersion.tar.gz"
        Write-Host "Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $tarball -UseBasicParsing
    }
    $hash = (Get-FileHash -Algorithm SHA256 $tarball).Hash.ToLowerInvariant()
    if ($hash -ne $XzSha256) {
        Remove-Item $tarball -Force
        throw "xz-$XzVersion.tar.gz has SHA-256 $hash, expected $XzSha256"
    }

    $src = Join-Path $Work "xz-$XzVersion"
    if (Test-Path $src) { Remove-Item -Recurse -Force $src }
    Invoke-Checked 'tar' @('-xzf', $tarball, '-C', $Work)

    $zcc = Join-Path $Work 'zcc.cmd'
    $zar = Join-Path $Work 'zar.cmd'
    $zranlib = Join-Path $Work 'zranlib.cmd'
    Set-Content -Encoding ascii $zcc "@zig cc -target $Target %*"
    Set-Content -Encoding ascii $zar '@zig ar %*'
    Set-Content -Encoding ascii $zranlib '@zig ranlib %*'

    $cmakeBuild = Join-Path $Work "xz-$XzVersion-build"
    if (Test-Path $cmakeBuild) { Remove-Item -Recurse -Force $cmakeBuild }
    $make = (Get-Command make).Source
    Invoke-Checked 'cmake' @(
        '-S', $src, '-B', $cmakeBuild,
        '-G', 'Unix Makefiles',
        "-DCMAKE_MAKE_PROGRAM=$make",
        "-DCMAKE_C_COMPILER=$zcc",
        "-DCMAKE_AR=$zar",
        "-DCMAKE_RANLIB=$zranlib",
        '-DCMAKE_SYSTEM_NAME=Windows',
        '-DCMAKE_BUILD_TYPE=Release',
        "-DCMAKE_INSTALL_PREFIX=$XzPrefix",
        '-DBUILD_SHARED_LIBS=OFF',
        '-DXZ_NLS=OFF',
        '-DXZ_THREADS=no',
        '-DXZ_DOC=OFF',
        '-DXZ_TOOL_XZ=OFF',
        '-DXZ_TOOL_XZDEC=OFF',
        '-DXZ_TOOL_LZMADEC=OFF',
        '-DXZ_TOOL_LZMAINFO=OFF',
        '-DXZ_TOOL_SCRIPTS=OFF',
        '-DXZ_TOOL_SYMLINKS=OFF',
        '-DXZ_TOOL_SYMLINKS_LZMA=OFF'
    )
    Invoke-Checked 'cmake' @('--build', $cmakeBuild, '--target', 'liblzma', '--parallel')
    Invoke-Checked 'cmake' @('--install', $cmakeBuild, '--component', 'liblzma_Development')
    if (-not (Test-Path $LibLzma)) {
        Invoke-Checked 'cmake' @('--install', $cmakeBuild)
    }
    if (-not (Test-Path $LibLzma)) {
        throw "liblzma.a was not installed to $LibLzma"
    }
}

Require-Tool 'zig'
Require-Tool 'cmake'
Require-Tool 'make'

if ($Clean -and (Test-Path $Build)) {
    Remove-Item -Recurse -Force $Build
}
New-Item -ItemType Directory -Force $Work | Out-Null

if (-not (Test-Path $LibLzma)) {
    Build-LibLzma
}

$sources = Get-ChildItem (Join-Path $Root 'src') -Filter '*.c' | ForEach-Object { $_.FullName }
$manifest = Join-Path $Root 'src\packguard.manifest'
$args = @(
    'cc', '-target', $Target,
    '-std=c17', '-O2', '-Wall', '-Wextra', '-Wpedantic',
    '-DLZMA_API_STATIC',
    '-I', (Join-Path $XzPrefix 'include'),
    '-o', $Exe
) + $sources + @($manifest, $LibLzma)
Invoke-Checked 'zig' $args

Write-Host "Built $Exe"
