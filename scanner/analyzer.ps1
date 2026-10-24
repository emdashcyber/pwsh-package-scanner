[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $InputRoot,

    [Parameter(Mandatory = $true)]
    [string] $MappingFile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module -Name PSScriptAnalyzer -RequiredVersion 1.25.0 -ErrorAction Stop

$mapping = Get-Content -LiteralPath $MappingFile -Raw -Encoding utf8 | ConvertFrom-Json
$rules = @(
    'PSAvoidUsingAllowUnencryptedAuthentication',
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    'PSAvoidUsingInvokeExpression',
    'PSAvoidUsingPlainTextForPassword',
    'PSAvoidUsingUsernameAndPasswordParams'
)
$results = [System.Collections.Generic.List[object]]::new()

foreach ($entry in $mapping) {
    $safeName = [System.IO.Path]::GetFileName([string] $entry.safeName)
    if ($safeName -notmatch '^file-[0-9]{5}\.(ps1|psm1|psd1|ps1xml|pssc)$') {
        throw 'Unsafe analyzer input file name.'
    }
    $path = Join-Path -Path $InputRoot -ChildPath $safeName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Analyzer input file is missing.'
    }
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $parseErrors) | Out-Null
    foreach ($parseError in $parseErrors) {
        $results.Add([ordered]@{
            ruleId = 'PowerShellParseError'
            severity = 'Error'
            message = [string] $parseError.Message
            file = [string] $entry.originalPath
            line = [int] $parseError.Extent.StartLineNumber
            endLine = [int] $parseError.Extent.EndLineNumber
        })
    }
    $diagnostics = Invoke-ScriptAnalyzer -Path $path -IncludeRule $rules -ErrorAction Stop
    foreach ($diagnostic in $diagnostics) {
        $results.Add([ordered]@{
            ruleId = [string] $diagnostic.RuleName
            severity = [string] $diagnostic.Severity
            message = [string] $diagnostic.Message
            file = [string] $entry.originalPath
            line = [int] $diagnostic.Extent.StartLineNumber
            endLine = [int] $diagnostic.Extent.EndLineNumber
        })
    }
}

$payload = [ordered]@{
    findings = @($results)
    powerShellVersion = $PSVersionTable.PSVersion.ToString()
    psscriptAnalyzerVersion = (Get-Module -Name PSScriptAnalyzer).Version.ToString()
}
Write-Output ('PSANALYZER_JSON:' + (ConvertTo-Json -InputObject $payload -Depth 5 -Compress))
