[CmdletBinding()]
param(
    [ValidateSet('hy2', 'vless')][string] $SourceProtocol,
    [string] $Source, [string] $Target,
    [ValidateRange(1, 65535)][int] $SourcePort,
    [ValidateRange(1, 65535)][int] $TargetPort,
    [string] $Key, [string] $SourceKey, [string] $TargetKey,
    [string[]] $WgMap = @(),
    [switch] $Apply, [switch] $CompareOnly, [switch] $Recover, [switch] $History
)

$ErrorActionPreference = 'Stop'
$engine = Join-Path $PSScriptRoot 'node_sync.py'
$options = @()
foreach ($entry in @(
    @('SourceProtocol','--source-protocol'), @('Source','--source'), @('Target','--target'),
    @('SourcePort','--source-port'), @('TargetPort','--target-port'), @('Key','--key'),
    @('SourceKey','--source-key'), @('TargetKey','--target-key')
)) {
    if ($PSBoundParameters.ContainsKey($entry[0])) {
        $value = [string] $PSBoundParameters[$entry[0]]
        if ($entry[0] -eq 'SourceProtocol') { $value = $value.ToLowerInvariant() }
        $options += @($entry[1], $value)
    }
}
foreach ($mapping in $WgMap) { $options += @('--wg-map', $mapping) }
if ($Apply) { $options += '--apply' }
if ($CompareOnly) { $options += '--compare' }
if ($Recover) { $options += '--recover' }
if ($History) { $options += '--history' }

$launcher = Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue
if ($launcher) {
    & $launcher.Source -3 -IB -X utf8 $engine @options
} else {
    $python = Get-Command python.exe -CommandType Application -ErrorAction Stop
    & $python.Source -IB -X utf8 $engine @options
}
exit $LASTEXITCODE
