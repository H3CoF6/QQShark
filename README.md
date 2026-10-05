# qqshark

QQNT 协议取证的妙妙小工具喵～。

**不注入、不 hook、不改动 QQ**，只读地扫描进程内存拿到会话密钥（a2/d2/d2key），再直接读网卡解密 MSF 流量。

- 密钥来源：运行时扫描 QQ 主进程（`wrapper.node`）的内存，用 C++ RTTI 自举定位 `SessionForNt` 实例后读取字段——零硬编码 RVA、零注入。
- 抓包来源：libpcap 读网卡 → TCP 重组 → MSF 帧解密（TEA）。网卡与端口默认 `auto` 自动识别。

## 命令

```sh
# 扫描密钥（macOS 需 sudo + 关 SIP；Linux 用 sudo）
qqshark scan [--pid <PID>] [--json]

# 枚举在线 QQ 进程并映射 UIN
qqshark procs [--json]

# 抓包（默认自动选网卡、自动识别端口、完整 hexdump + 展开正文）
qqshark capture [-i auto] [-p auto] [--d2key <32hex>] [--pid <PID>] \
                [-w out.pcap] [--only-head] [--no-expand] [-n <N>]

# 一条龙：先扫进程与 UIN，再取 d2key 抓包
qqshark live [-i auto] [-p auto] [--pid <PID>] [-w out.pcap] \
             [--only-head] [--no-expand] [-n <N>]

# 在终端展开一段 hex（可先按 d2key 做 TEA 解密）
qqshark decode <HEX|- > [--d2key <32hex>] [--only-head] [--no-expand]
```

关键参数：

- `-i, --iface`：抓包接口，默认 `auto`（自动选默认路由出口网卡），也可显式填 `en0`/`wlan0` 等。
- `-p, --port`：MSF 端口，默认 `auto`——按 MSF 帧签名**持续**识别，抓包过程中端口从
  14000 切到 80/443 等也能自动纳管，不会漏抓。也可写固定端口 `14000`、多个端口
  `14000,443,80`，或用 `auto,443` 在保留固定端口的同时继续发现新端口。
- `--d2key`：直接给 32 字符 hex 密钥；省略则由 `--pid` 自动扫描。
- `--only-head`（别名 `--no-hex`）：只显示 hexdump 前 128 字节预览；默认打印完整 hexdump。
- `--no-expand`：不展开正文的 protobuf/JCE 树；默认展开。

收发包用 TUI 方框展示，Ctrl+C 或 ESC 结束。
