$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModelDir = Join-Path $ScriptDir "model_int8"
$Archive = Join-Path $ScriptDir "packguard-stage2-v6-onnx.tar.gz"
$Url = "https://github.com/asembarhoush-dotcom/PackGuard/releases/download/v2.0-model/packguard-stage2-v6-onnx.tar.gz"
$ExpectedSha = "9F6B70019ECEE915E4C39C697E1199F8D6A664EA6EBB3F9101B7E2BF8CF415A7"

New-Item -ItemType Directory -Force -Path $ModelDir | Out-Null
Write-Host "[PackGuard Stage 2 v6] Downloading ONNX INT8 model + real ModernBERT tokenizer (12.41 MB)..."
Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing

$ActualSha = (Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToUpperInvariant()
if ($ActualSha -ne $ExpectedSha) {
    Remove-Item -Force $Archive -ErrorAction SilentlyContinue
    throw "SHA-256 mismatch! expected=$ExpectedSha actual=$ActualSha"
}

tar -xzf $Archive -C $ModelDir
Remove-Item -Force $Archive -ErrorAction SilentlyContinue

Write-Host "[PackGuard Stage 2 v6] Installed to $ModelDir (SHA-256 verified)."
Get-ChildItem $ModelDir | Select-Object Name, Length
