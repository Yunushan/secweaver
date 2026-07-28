$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$SecWeaverRoot = Split-Path -Parent $PSScriptRoot
$SourceRoot = Join-Path $SecWeaverRoot "src"
if (Test-Path (Join-Path $SourceRoot "secweaver")) {
    if ([string]::IsNullOrWhiteSpace($env:PYTHONPATH)) {
        $env:PYTHONPATH = $SourceRoot
    } else {
        $env:PYTHONPATH = "$SourceRoot$([IO.Path]::PathSeparator)$env:PYTHONPATH"
    }
}

$PythonCommand = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $PythonCommand -m secweaver @args
exit $LASTEXITCODE
