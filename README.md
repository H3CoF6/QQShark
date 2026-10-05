# qqshark

QQNT 零注入跨平台抓包工具喵～

非侵入式：只读进程内存 / 只读打开数据库锁 / 只从网卡抓包，不注入、不 hook、不修改 QQ。

## 功能

- `scan`：运行时扫描某 pid 的 a2/d2/d2key（RTTI 自举，零硬编码 RVA）
- `procs`：枚举全部在线 QQ 进程并映射到 UIN（解密 login.db + 文件锁探测）
- `capture`：原始抓包 + MSF 帧解密（TUI 方框输出，Ctrl+C/ESC 结束）
- `live`：一条龙，先扫进程与 UIN，再自动取 d2key 抓包
- `decode`：在终端展开一段 hex（hexdump + TEA 解密（可选）+ protobuf/JCE 解析）

## 平台支持

| 平台 | 内存扫描 (scan) | 抓包 (capture) | 数据目录/UIN 映射 |
| --- | --- | --- | --- |
| Linux | `sudo`（或 CAP_SYS_PTRACE）| `sudo`（或 CAP_NET_RAW）| 支持 |
| Windows | 管理员终端 | 管理员终端 + Npcap | 支持 |
| macOS | `sudo` 且关闭 SIP | `sudo`（无需关 SIP）| 支持 |

### macOS 说明

- 抓包：macOS 的 BPF 设备（`/dev/bpf*`）默认仅 root 可读，用 `sudo` 运行即可，不需要关闭 SIP。默认网卡 `auto` 会自动选默认路由出口（通常是 `en0`）。
- 内存扫描：QQ 启用了强化运行时（hardened runtime），即使 root，`task_for_pid` 也会被 `taskgated` 拒绝（`kern_return=5`）。只有关闭 SIP 后才可读取：重启进恢复模式执行 `csrutil disable`，再重启。抓包不受此限制。
- 默认 MSF 端口：macOS/Linux 为 `14000`，Windows 为 `443`；都可用 `-p/--port` 覆盖，或 `-p auto` 按流量自动识别。

## 用法

```sh
# 扫描密钥（macOS 需 sudo + 关 SIP）
sudo ./qqshark scan --pid <QQ_PID>

# 枚举进程与 UIN
sudo ./qqshark procs

# 抓包（自动选网卡、自动识别端口）
sudo ./qqshark capture            # 默认 -i auto -p <平台默认>
sudo ./qqshark capture -p auto    # 端口也自动识别
sudo ./qqshark capture -i en0 -p 14000 --d2key <32hex>

# 一条龙
sudo ./qqshark live
```
