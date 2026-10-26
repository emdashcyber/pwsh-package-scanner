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
$warnings = [System.Collections.Generic.List[string]]::new()

foreach ($entry in $mapping) {
    $safeName = [System.IO.Path]::GetFileName([string] $entry.safeName)
    if ($safeName -notmatch '^file-[0-9]{5}\.(ps1|psm1|psd1)$') {
        throw 'Unsafe analyzer input file name.'
    }
    $path = Join-Path -Path $InputRoot -ChildPath $safeName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Analyzer input file is missing.'
    }
    $source = Get-Content -LiteralPath $path -Raw -Encoding utf8
    $isDscConfiguration = $source -match '(?im)^\s*Configuration\s+[A-Za-z_][A-Za-z0-9_.-]*\s*\{'
    $tokens = $null
    $parseErrors = $null
    $dscContextUnavailable = $false
    $dscContextPattern = '(?i)(unable to find DSC schema store|configuration keyword is not supported|DSC.*schema store|PS DSC.*not installed|DirectoryNotFoundException)'
    try {
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $parseErrors) | Out-Null
    } catch {
        if ($isDscConfiguration -and [string] $_.Exception -match $dscContextPattern) {
            $dscContextUnavailable = $true
            $parseErrors = @()
        } else {
            throw
        }
    }
    if (-not $dscContextUnavailable) {
        $dscContextUnavailable = $isDscConfiguration -and @($parseErrors | Where-Object {
            [string] $_.Message -match $dscContextPattern
        }).Count -gt 0
    }
    if ($dscContextUnavailable) {
        $warnings.Add(([string] $entry.originalPath) + ': DSC syntax validation was skipped because the runner lacks the required DSC schema context.')
    } else {
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
    }
    try {
        $diagnostics = Invoke-ScriptAnalyzer -Path $path -IncludeRule $rules -ErrorAction Stop
    } catch {
        if ($isDscConfiguration -and [string] $_.Exception -match $dscContextPattern) {
            $diagnostics = @()
            if (-not $dscContextUnavailable) {
                $warnings.Add(([string] $entry.originalPath) + ': DSC syntax validation was skipped because the runner lacks the required DSC schema context.')
            }
            $dscContextUnavailable = $true
        } else {
            throw
        }
    }
    foreach ($diagnostic in $diagnostics) {
        $diagnosticName = [string] $diagnostic.RuleName
        $diagnosticMessage = [string] $diagnostic.Message
        $diagnosticIndicatesDscUnavailable = ($diagnosticName -match '(?i)configurationnotallowed') -or ($diagnosticMessage -match $dscContextPattern)
        if ($isDscConfiguration -and $diagnosticIndicatesDscUnavailable) {
            if (-not $dscContextUnavailable) {
                $warnings.Add(([string] $entry.originalPath) + ': DSC syntax validation was skipped because the runner lacks the required DSC schema context.')
            }
            $dscContextUnavailable = $true
            continue
        }
        if ([string] $diagnostic.Severity -eq 'ParseError') {
            continue
        }
        if ($dscContextUnavailable -and $diagnosticName -match '(?i)(parse|unexpectedtoken|missingendcurlybrace|configurationnotallowed)') {
            continue
        }
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
    warnings = @($warnings)
    powerShellVersion = $PSVersionTable.PSVersion.ToString()
    psscriptAnalyzerVersion = (Get-Module -Name PSScriptAnalyzer).Version.ToString()
}
Write-Output ('PSANALYZER_JSON:' + (ConvertTo-Json -InputObject $payload -Depth 5 -Compress))
