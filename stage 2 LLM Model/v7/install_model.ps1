$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModelDir = Join-Path $ScriptDir "model_int8"
$Archive = Join-Path $ScriptDir "packguard-stage2-v7-onnx.tar.gz"
$Url = if ($env:PACKGUARD_V7_MODEL_URL) { $env:PACKGUARD_V7_MODEL_URL } else { "https://github.com/asembarhoush-dotcom/PackGuard/releases/download/v2.0-model/packguard-stage2-v7-onnx.tar.gz" }
$ExpectedSha = if ($env:PACKGUARD_V7_SHA256) { $env:PACKGUARD_V7_SHA256.ToUpperInvariant() } else { "F3E2881AA71B1B20F7D51F16E4AE02CBC67BDAD481D6EAA923126B174E9A83D4" }

New-Item -ItemType Directory -Force -Path $ModelDir | Out-Null
Write-Host "[PackGuard Stage 2 v7] Downloading ONNX INT8 model + real ModernBERT tokenizer..."
Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing

$ActualSha = (Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToUpperInvariant()
if ($ExpectedSha -ne "PENDING_V7_RELEASE_SHA256" -and $ActualSha -ne $ExpectedSha) {
    Remove-Item -Force $Archive -ErrorAction SilentlyContinue
    throw "SHA-256 mismatch! expected=$ExpectedSha actual=$ActualSha"
}

tar -xzf $Archive -C $ModelDir
Remove-Item -Force $Archive -ErrorAction SilentlyContinue

Write-Host "[PackGuard Stage 2 v7] Installed to $ModelDir (sha256=$ActualSha)."
Get-ChildItem $ModelDir | Select-Object Name, Length
