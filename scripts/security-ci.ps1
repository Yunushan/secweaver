$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$SecWeaverRoot = Split-Path -Parent $PSScriptRoot
Set-Location $SecWeaverRoot
$ReportDir = if ($env:SECWEAVER_REPORT_DIR) {
    $env:SECWEAVER_REPORT_DIR
} else {
    "secweaver-reports"
}

& (Join-Path $SecWeaverRoot "bin/secweaver.ps1") `
    --config secweaver.toml `
    scan `
    --report-dir $ReportDir `
    @args
exit $LASTEXITCODE
