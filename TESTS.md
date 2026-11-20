# 自动化验证

## 结果

本次在隔离的 Linux 虚拟机中运行完整测试，**28 项通过**，包括 11 项原生脚本验证。Windows 上的 Python 测试为 15 项通过、13 项因环境限制跳过。

| 验证 | 结果与环境 |
| --- | --- |
| 工作流、SSH 标准输入帧和 Linux 一行启动 | 通过。Linux 执行环境，使用隔离的目标状态及模拟下载端 |
| 两种原生创建器的本地 / WG-NAT 分支 | 通过。运行固定上游安装器提取出的真实 Bash，模拟 systemd、DNS、网络核心和 nft 外部接口 |
| 原生删除与独立端口保护 | 通过。在隔离目录执行两套原生 `cleanup_one`，核对另一端口余额和本轮残留 |
| 精确余额、零余额、无周期、两种原生重置 | 通过。在隔离目录执行两套原生配额库。两边的重置函数都按原始总额恢复 |
| 失败补偿与恢复 | 通过。模拟原生重建失败和启动失败，核对余额恢复、节点清理及原生待重建状态 |
| HY2 和 VLESS 来源无锁读取 | 通过。用两套固定原生脚本读取有流量的节点；原生锁文件缺失或由另一会话持有时均可完成，已有锁文件的内容和修改时间保持一致 |

测试覆盖严格同端口、两个方向、有效空源和损坏空源的区分、独立删除确认、改动后的计划作废、过期样本、配额或无配额冲突、故障后停止其余操作。即使端口号集合相同，来源节点文件在执行中发生变化也会取消剩余删除。Windows 上运行了可用的 Python 测试。真实 VPS 的端到端连接、Windows PowerShell 启动入口和真实 systemd/nftables 承载仍需在安装环境验收。

## 普通测试

```bash
python3 -B -m unittest discover -s tests -v
```

普通测试的原生脚本用例会在缺少已固定的上游副本时标为跳过。

## 重跑原生脚本验证

任选本地测试目录，并以表中名字存放对应的上游文件。测试从它们提取实际安装的 Bash，核对完整 SHA-256，并在临时目录模拟外部依赖。

| 本地文件名 | 上游固定版本 |
| --- | --- |
| `hy2jieshu-hy2.sh` | [HY2 安装器](https://raw.githubusercontent.com/liucong552-art/hy2jieshu/43c7c7df729bc6e71de734eb83a6960db8de7aac/hy2.sh) |
| `hy2jieshu-natjichang.sh` | [HY2 NAT 安装器](https://raw.githubusercontent.com/liucong552-art/hy2jieshu/43c7c7df729bc6e71de734eb83a6960db8de7aac/natjichang.sh) |
| `jieshu-vless.sh` | [VLESS 安装器](https://raw.githubusercontent.com/liucong552-art/jieshu/1ac27d2d82c545c12b35638bd9f0ac3193c9d2b4/vless.sh) |
| `jieshu-natjichang.sh` | [VLESS NAT 安装器](https://raw.githubusercontent.com/liucong552-art/jieshu/1ac27d2d82c545c12b35638bd9f0ac3193c9d2b4/natjichang.sh) |

```bash
HY2_VLESS_TEST_UPSTREAM=/path/to/read-only-upstream-copies python3 -B -m unittest discover -s tests -v
```

可以指定 `HY2_VLESS_TEST_TMP` 使用一个已经存在的本地临时目录。测试只调用这次模拟的原生资源。

