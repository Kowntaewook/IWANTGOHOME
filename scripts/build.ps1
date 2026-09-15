$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "finder.ps1") build @args
exit $LASTEXITCODE
