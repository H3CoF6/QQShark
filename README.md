# qqshark

QQ NT 协议取证工具：**RTTI 自举密钥扫描** + **全进程 UIN 映射** + **原始抓包解密**。
非侵入式，运行时自举，零硬编码 RVA。支持 Linux / macOS / Windows。

## 功能

- `scan`    运行时扫描某 pid 的 `a2` / `d2` / `d2key`（RTTI 自举，零硬编码 RVA）
- `procs`   枚举全部在线 QQ 进程并映射到 UIN（`login.db` 解密 + 数据库占用探测）
- `capture` 原始抓包 + MSF 帧解密（TUI 方框输出，默认前 128 字节 hex）
- `live`    一条龙：先扫进程与 UIN，再自动取 `d2key` 抓包
- `decode`  在终端展开一段 hex：TEA 解密（可选）+ protobuf/JCE 解析

## 构建

```bash
cargo build --release
```

### Windows 前置

1. 安装 [Npcap](https://npcap.com/dist/)（抓包用），安装时勾选
   **Install Npcap in WinPcap API-compatible Mode**，确保 `wpcap.dll` / `Packet.dll`
   位于 `C:\Windows\System32\Npcap\`（或与本工具 exe 同目录）。
2. 构建期需要 `wpcap.lib` 导入库。仓库已内置 x64 版本
   （`vendor/npcap/x64/wpcap.lib`）；若使用自定义 Npcap SDK，可设环境变量
   `NPCAP_SDK_DIR` 指向其安装目录。
3. **以管理员身份运行**（等价于 Linux 的 root / `CAP_NET_RAW`）：密钥扫描
   （`ReadProcessMemory`）与抓包都需要管理员权限。

## 使用

```bash
# 列出在线 QQ 进程与 UIN 映射
qqshark procs

# 扫描指定（或自动推断的）进程密钥
qqshark scan --pid 28508
qqshark scan --json

# 抓包并解密（Linux 默认接口 Meta；Windows 需填 Npcap 设备名）
qqshark capture -i "Meta"
qqshark capture -i "\Device\NPF_{...}" -n 20
```

### Windows 抓包说明

- 先跑一次 `qqshark capture`（不给 `-i`）会列出全部 Npcap 设备名，挑物理网卡或
  代理/TUN 对应的虚拟网卡。
- 若只列出“回环适配器（Adapter for loopback traffic capture）”：说明 Npcap 未把
  物理网卡暴露给 WinPcap 兼容层，重装 Npcap 并勾选安装到所有网卡即可。
- 结束抓包：`Ctrl+C` 或按 `ESC` / `q`（与 Linux 行为一致）。

## 许可

仅供安全研究与取证学习使用，请遵守当地法律法规。
