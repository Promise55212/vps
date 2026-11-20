# HY2 ↔ VLESS 临时节点镜像

一次从你选定的来源 VPS 读取临时节点，并让目标 VPS 按相同端口同步。切换来源可反向运行。操作使用原项目的审计、删除、创建和配额管理，SSH 结束即退出。

| 来源与目标的端口 | 操作 |
| --- | --- |
| 两边都有，均有配额 | 按来源实时剩余字节设置目标本期余额，继续使用目标原总额、到期和重置计划 |
| 两边都有，均无配额 | 跳过，两边继续无配额 |
| 仅来源有 | 用目标协议的原生入口创建同端口，继承来源的绝对到期时刻和适用的策略 |
| 仅目标有 | 单独确认删除名单后，用目标协议原生清理程序删除该临时节点 |

例如来源 40013 本期剩 80.46 GiB，目标原周期总额 200 GiB。工具使用来源的原始字节数设置本期余额，下次按目标原计划恢复 200 GiB。无自动重置的 `NEXT_RESET_EPOCH=0`、`RESET_INTERVAL_SECONDS=0` 组合也是有效状态。

## 从 GitHub 一行启动

把压缩包中 `node-sync/` 内的文件上传到你自己的仓库根目录。从 GitHub 复制该次提交的完整 40 位 SHA，替换下方的 `OWNER/REPO` 和 `COMMIT_SHA`。示例默认只读，下载文件用毕从**操作电脑**清理。

### Windows PowerShell

本机使用 Windows OpenSSH 与 Python 3.8+。有 `py` 启动器时执行这一行。

```powershell
$repo='OWNER/REPO';$rev='COMMIT_SHA';if($rev -cnotmatch '^[0-9a-f]{40}$'){throw '请填写完整的 40 位小写提交 SHA'};$f=Join-Path ([IO.Path]::GetTempPath()) ('hvs-'+[guid]::NewGuid()+'.py');try{Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/$repo/$rev/node_sync.py" -OutFile $f;py -3 -IB -X utf8 $f --compare}finally{Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue}
```

只有 `python.exe` 时，将 `py -3` 换成 `python`。用解压文件直接运行时可以执行 `py -3 -IB -X utf8 .\node_sync.py --compare`，也可在 PowerShell 调用 `node-sync.ps1 -CompareOnly`。

### Linux

```bash
bash -c 'set -e; repo=$1; rev=$2; shift 2; [[ $rev =~ ^[a-f0-9]{40}$ ]]; f=$(mktemp); trap '"'"'rm -f -- "$f"'"'"' EXIT; curl --proto "=https" -fsSL --max-time 60 "https://raw.githubusercontent.com/$repo/$rev/node_sync.py" -o "$f"; python3 -IB -X utf8 "$f" "$@"' _ 'OWNER/REPO' 'COMMIT_SHA' --compare
```

用解压文件直接运行时执行 `python3 -IB -X utf8 node_sync.py --compare`。

## 从对账到执行

1. 先用平时的 SSH 方式登录过两台 VPS，确认它们的主机指纹在本机的 `known_hosts` 里。两台 VPS 都用各自的原生节点管理器、独立主机标识、Python 3.8+、Bash、nftables、systemd 和 root SSH。
2. 启动时输入来源协议 `hy2` 或 `vless`、两台 VPS 及 SSH 端口。默认沿用 OpenSSH 配置，若有 `~/.ssh/vps_root_ed25519` 会优先使用。也可以传 `--key`、`--source-key` 和 `--target-key`。私钥保留在本机。
3. 对账会独立核对两边的原生审计、文件、配额归属、监听进程和原生锁，再列出端口数量、待建、待删、待调余额、无配额和冲突。一个端口只能对应一个原生临时节点。默认按相同端口匹配。通过 `--history` 可以查看各端已保存的每日流量。
4. 正式执行把 `--compare` 换成 `--apply`。先阅读新计划，再输入 `APPLY`。如果有待删端口，按屏幕显示另输 `DELETE 数量`，例如 `DELETE 2`。取消或输错时本轮止于预检。
5. 工具重新按固定顺序锁住两台的原生节点管理，核对计划，再依次创建、对齐余额、清理多余节点。配额操作沿用各自原生配额锁。结束后自动重新审计，并逐端口报告结果和实时余额。新节点输出在目标 root 终端查看链接的命令。

来源库存不完整、任一端服务状态异常、目标端口被占用、余额超过目标总额或一端有配额而另一端无配额都会阻止写入。两端已有节点到期时间或周期设置不同且各自健康时，报告差异，目标按自己的设置继续。端口 443 和两台实际主端口受保护。

工具在每个写入前重新读取来源实时余额。写入前再次核对目标配额周期和端口归属。采样过时或两端时间差超过 30 秒时停止，校准时钟后重新对账。连接持续使用时，核对读到的余额可能已低于刚设置的值。先建后删使原生删除排在校验之后，预检会显示目标的预计临时峰值节点数。

## 原生兼容和创建规则

- 本版本按以下上游安装器审核了原生审计、创建、清理、临时服务、配额与重置脚本。预检会逐文件核对已审核的 SHA-256。发现路径缺失或版本不符时显示路径，版本不符同时给出实际哈希。适配其他安装版时，需要其对应原生脚本内容及只读审计，才能重新验证入口。 [HY2 上游](https://github.com/liucong552-art/hy2jieshu/tree/43c7c7df729bc6e71de734eb83a6960db8de7aac) · [VLESS 上游](https://github.com/liucong552-art/jieshu/tree/1ac27d2d82c545c12b35638bd9f0ac3193c9d2b4)
- 新建以来源 `CREATE_EPOCH`、`DURATION_SECONDS` 算同一个到期时刻，原生管理器启动服务前就装好源节点的原始总配额、本期余额、周期和绝对重置时刻。零余额会按已耗尽建立保护，等原生周期重置。密码、UUID 和入口发布资料由目标原生环境提供。
- 使用来源的本地或 WG-NAT 出口类型、IPv4/IPv6 入站、IP 上限和 Sticky 秒数。WG-NAT 默认检查目标的同名接口及本机标记路由、握手和原生组件。接口确实对应但名字不同时，使用 `--wg-map wg-source=wg-target`。IPv6 使用目标原有的发布域名。
- 临时脚本程序通过 SSH 标准输入传输。适配器在内存中把准确时间和额度交给审核过的原生创建流程，服务器的原生脚本继续供日常业务使用。正常完成时 SSH 退出、原生锁释放，恢复记录清除。限速由目标机管理，历史流量展示已保存记录。

## 中断和恢复

操作按端口提交。单个创建失败时尝试用原生清理撤回该节点。单个配额重建失败时尝试恢复写入前余额。任一失败停止后续操作并尽可能复审，已经通过校验的端口保留结果。

事务进行时目标用一个 root 专用恢复记录。普通结束后清除。断电、SSH 中断或原生清理失败时，可用同一来源和目标改用 `--recover`，按屏幕所示输入 `RECOVER 端口`。它重新检查端口归属和来源后处理那一次中断。已执行的退款删除如果需要恢复原凭据，应使用既有 VPS 备份。若检测到另一账号接管端口或冲突无法消除，恢复停在该端口并保留记录。

## 仓库和测试

```text
node_sync.py
node-sync.ps1
README.md
CHANGES.md
TESTS.md
tests/
  test_sync.py
  test_native_contract.py
```

在仓库根目录运行 `python3 -B -m unittest discover -s tests -v`。`TESTS.md` 说明如何用两个固定上游安装器重跑 Bash、配额和清理验证。

