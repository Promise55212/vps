$ErrorActionPreference = 'Stop'

function Read-SshPort([string]$label) {
    $value = Read-Host "$label SSH 端口，直接回车用 22"
    if ([string]::IsNullOrWhiteSpace($value)) { return 22 }
    $port = 0
    if (-not [int]::TryParse($value, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw '端口应为 1 到 65535 之间的整数。'
    }
    return $port
}

$profileDir = Join-Path $env:LOCALAPPDATA 'HY2VLESS-Sync'
$profileFile = Join-Path $profileDir 'connection.json'
Write-Host '1  只读对账（直接回车）'
Write-Host '2  正式同步（先看计划，再确认写入）'
Write-Host '3  重新设置源机和目标机，然后只读对账'
$choice = ([string](Read-Host '请选择')).Trim()
if ($choice -notin @('', '1', '2', '3')) { throw '请输入 1、2 或 3。' }

$configure = $choice -eq '3' -or -not (Test-Path -LiteralPath $profileFile -PathType Leaf)
if ($configure) {
    Write-Host '这次设置会保存在本机，下次可直接选择操作。'
    $protocol = ([string](Read-Host '源机协议 hy2 / vless，直接回车用 hy2')).Trim().ToLowerInvariant()
    if (-not $protocol) { $protocol = 'hy2' }
    $source = ([string](Read-Host '源机 IP 或 SSH 别名（只读）')).Trim()
    $target = ([string](Read-Host '目标机 IP 或 SSH 别名（同步时修改）')).Trim()
    $connection = [ordered]@{
        Protocol = $protocol
        Source = $source
        Target = $target
        SourcePort = (Read-SshPort '源机')
        TargetPort = (Read-SshPort '目标机')
    }
} else {
    $connection = Get-Content -LiteralPath $profileFile -Encoding UTF8 -Raw | ConvertFrom-Json
}

if ($connection.Protocol -notin @('hy2', 'vless') -or -not $connection.Source -or -not $connection.Target -or
    $connection.Source -eq $connection.Target) {
    throw '请重新运行并选择 3，填写源机协议和两台不同机器的地址。'
}

if ($configure) {
    $null = New-Item -ItemType Directory -Path $profileDir -Force
    $profileTemp = Join-Path $profileDir ('connection-' + [guid]::NewGuid() + '.json')
    try {
        $connection | ConvertTo-Json | Set-Content -LiteralPath $profileTemp -Encoding UTF8
        Move-Item -LiteralPath $profileTemp -Destination $profileFile -Force
    } finally {
        Remove-Item -LiteralPath $profileTemp -ErrorAction SilentlyContinue
    }
}

$mode = '--compare'
if ($choice -eq '2') { $mode = '--apply' }
$targetProtocol = if ($connection.Protocol -eq 'hy2') { 'vless' } else { 'hy2' }
Write-Host ('源机 {0} {1}:{2} → 目标机 {3} {4}:{5}' -f $connection.Protocol, $connection.Source,
    $connection.SourcePort, $targetProtocol, $connection.Target, $connection.TargetPort)

# Keep the launcher on the engine revision recorded in LIVE_TEST.md.
$engineUrl = 'https://raw.githubusercontent.com/liucong552-art/vps/bde7adb6a630532992d8c29afadf3a37d0c713bf/node_sync.py'
$engine = Join-Path ([IO.Path]::GetTempPath()) ('hvs-' + [guid]::NewGuid() + '.py')
$options = @(
    $mode, '--source-protocol', $connection.Protocol,
    '--source', $connection.Source, '--target', $connection.Target,
    '--source-port', [string]$connection.SourcePort, '--target-port', [string]$connection.TargetPort
)
try {
    Invoke-WebRequest -UseBasicParsing -Uri $engineUrl -OutFile $engine
    $python = Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($python) {
        & $python.Source -3 -IB -X utf8 $engine @options
    } else {
        $python = Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
        & $python.Source -IB -X utf8 $engine @options
    }
} finally {
    Remove-Item -LiteralPath $engine -ErrorAction SilentlyContinue
}
