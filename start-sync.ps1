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

$ssh = Get-Command ssh.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ssh) { throw '这台电脑需要 Windows OpenSSH 客户端（ssh 命令）。' }

$python = Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$pythonArgs = @('-3')
if (-not $python) {
    $python = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $pythonArgs = @()
}
if (-not $python) { throw '这台电脑需要 Python 3.8 或更新版本。' }

Write-Host '1  只读对账（直接回车）'
Write-Host '2  正式同步（先看计划，再确认写入）'
$choice = ([string](Read-Host '请选择')).Trim()
if ($choice -notin @('', '1', '2')) { throw '请输入 1 或 2。' }

$direction = ([string](Read-Host '同步方向（1 = HY2 → VLESS，2 = VLESS → HY2）')).Trim()
$protocol = switch ($direction) {
    '1' { 'hy2' }
    '2' { 'vless' }
    default { throw '请选择同步方向 1 或 2。' }
}

$source = ([string](Read-Host '源机 IP 或 SSH 别名（只读）')).Trim()
$target = ([string](Read-Host '目标机 IP 或 SSH 别名（同步时修改）')).Trim()
if (-not $source -or -not $target -or $source -eq $target) {
    throw '请输入两台不同机器的地址。'
}
$sourcePort = Read-SshPort '源机'
$targetPort = Read-SshPort '目标机'

$mode = '--compare'
if ($choice -eq '2') { $mode = '--apply' }
$targetProtocol = if ($protocol -eq 'hy2') { 'vless' } else { 'hy2' }
Write-Host ('源机 {0} {1}:{2} → 目标机 {3} {4}:{5}' -f $protocol, $source, $sourcePort, $targetProtocol, $target, $targetPort)

# Keep the launcher on the engine revision recorded in LIVE_TEST.md.
$engineUrl = 'https://raw.githubusercontent.com/liucong552-art/vps/bde7adb6a630532992d8c29afadf3a37d0c713bf/node_sync.py'
$engine = Join-Path ([IO.Path]::GetTempPath()) ('hvs-' + [guid]::NewGuid() + '.py')
$options = @(
    $mode, '--source-protocol', $protocol, '--source', $source, '--target', $target,
    '--source-port', [string]$sourcePort, '--target-port', [string]$targetPort
)
try {
    Invoke-WebRequest -UseBasicParsing -Uri $engineUrl -OutFile $engine -TimeoutSec 30
    & $python.Source @pythonArgs -IB -X utf8 $engine @options
} finally {
    Remove-Item -LiteralPath $engine -ErrorAction SilentlyContinue
}
