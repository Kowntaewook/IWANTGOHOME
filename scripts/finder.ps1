$ErrorActionPreference = "Stop"
$runner = Join-Path $PSScriptRoot "control.py"
if (Get-Command python3 -ErrorAction SilentlyContinue) {
    & python3 $runner @args
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $runner @args
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $runner @args
} else {
    throw "Python 3.11+ is required for the host lifecycle helper."
}
exit $LASTEXITCODE
