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

function Find-PythonManager {
    $command = Get-Command pymanager.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }

    # Package aliases work even when the current shell has not picked up a PATH change.
    foreach ($suffix in 'qbz5n2kfra8p0', '3847v3x7pw1km') {
        $path = Join-Path $windowsApps "PythonSoftwareFoundation.PythonManager_$suffix\pymanager.exe"
        if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    }
}

function Find-SyncPython([string]$manager) {
    $ErrorActionPreference = 'SilentlyContinue'
    $PSNativeCommandUseErrorActionPreference = $false
    $candidates = @(
        # Discover direct executables instead of executing the Windows Store placeholder.
        Get-Command python.exe, python3.exe -All -CommandType Application |
            Where-Object { (Split-Path -Parent $_.Source) -ne $windowsApps } |
            Select-Object -ExpandProperty Source

        foreach ($launcher in Get-Command py.exe -All -CommandType Application) {
            & $launcher.Source -0p 2>$null | ForEach-Object {
                if ($_ -match '^\s*-\S+\s+(?:\*\s+)?(.+?\.exe)\s*$') { $Matches[1] }
            }
        }

        if ($manager) { & $manager list --format=exe 2>$null }
        Get-ChildItem -LiteralPath $windowsApps -File -Filter 'python3.*.exe' |
            Select-Object -ExpandProperty FullName
        Get-ChildItem -LiteralPath $windowsApps -Directory -Filter 'PythonSoftwareFoundation.Python.*' |
            ForEach-Object { Join-Path $_.FullName 'python.exe' }
    )
    $probe = "import sys; print('HY2VLESS-PYTHON') if (3, 8) <= sys.version_info < (4,) else sys.exit(1)"
    foreach ($path in ($candidates | Select-Object -Unique)) {
        if ($path -and [IO.Path]::IsPathRooted($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            $result = & $path -IB -c $probe 2>$null
            if ($LASTEXITCODE -eq 0 -and $result -ceq 'HY2VLESS-PYTHON') { return $path }
        }
    }
}

function Install-PythonManager {
    $PSNativeCommandUseErrorActionPreference = $false
    $winget = Get-Command winget.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($winget) {
        & $winget.Source install --id 9NQ7512CXL7T --exact --source msstore --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Host
        if ($LASTEXITCODE -eq 0) { return }
    }

    $windowsPowerShell = Get-Command powershell.exe -CommandType Application | Select-Object -First 1
    $install = 'Add-AppxPackage -ErrorAction Stop -AppInstallerFile https://www.python.org/ftp/python/pymanager/pymanager.appinstaller'
    & $windowsPowerShell.Source -NoProfile -NonInteractive -Command $install | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw '无法自动安装 Python 安装管理器。请检查网络或 Windows 的安装限制，再运行同一行。'
    }
}

$sshClient = Get-Command ssh.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty Source
if (-not $sshClient) {
    $nativeSsh = Join-Path $env:SystemRoot 'Sysnative\OpenSSH\ssh.exe'
    if (Test-Path -LiteralPath $nativeSsh -PathType Leaf) { $sshClient = $nativeSsh }
}
if (-not $sshClient) { throw '这台电脑需要 Windows OpenSSH 客户端（ssh 命令）。' }

$windowsApps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
$manager = Find-PythonManager
$python = Find-SyncPython $manager
if (-not $python) {
    Write-Host '未找到可用的 Python，正在为当前 Windows 用户安装官方最新稳定版。'
    if (-not $manager) {
        Install-PythonManager
        $manager = Find-PythonManager
    }
    if (-not $manager) { throw '安装管理器暂时不可用。请重新打开 PowerShell，再运行同一行。' }
    & $manager install --yes --source=https://www.python.org/ftp/python/index-windows.json 3
    if ($LASTEXITCODE -ne 0) { throw 'Python 安装失败。请检查上方的安装提示，再运行同一行。' }
    $python = Find-SyncPython $manager
    if (-not $python) { throw '安装完成后未检测到可用的 Python。请重新打开 PowerShell，再运行同一行。' }
}

Write-Host '1  只读对账（直接回车）'
Write-Host '2  正式同步（先看计划，再确认写入）'
Write-Host '3  详细对账（含精确字节和节点参数）'
$choice = ([string](Read-Host '请选择')).Trim()
if ($choice -notin @('', '1', '2', '3')) { throw '请输入 1、2 或 3。' }

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

# Pin the engine revision used by the Windows launcher.
$engineUrl = 'https://raw.githubusercontent.com/Promise55212/vps/25f87be0958186a0ea69e1552ec0f815ab0db802/node_sync.py'
$engine = Join-Path ([IO.Path]::GetTempPath()) ('hvs-' + [guid]::NewGuid() + '.py')
$options = @(
    $mode, '--source-protocol', $protocol, '--source', $source, '--target', $target,
    '--source-port', [string]$sourcePort, '--target-port', [string]$targetPort,
    '--ssh-client', $sshClient
)
if ($choice -eq '3') { $options += '--details' }
try {
    Invoke-WebRequest -UseBasicParsing -Uri $engineUrl -OutFile $engine -TimeoutSec 30
    & $python -IB -X utf8 $engine @options
} finally {
    Remove-Item -LiteralPath $engine -ErrorAction SilentlyContinue
}
