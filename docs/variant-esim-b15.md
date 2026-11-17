# F50 Pro 内置双 eSIM 版 (`board_id=1` / `B15`) 开发与刷机说明

## 1. 硬件识别与差异摘要

| 项目 | 参数 |
| :--- | :--- |
| 设备平台 | ZTE `MU3356` / Unisoc `UMS9632` (`arm64`) |
| 出厂系统 | Android 15 (`SDK 35`, `vendor_boot` hardware `ums9632_1h10_mbb`) |
| Board ID (`/proc/driver/board_id`) | `1` |
| SIM 拓扑 | **纯内置双 eSIM**（出厂多为移动 + 电信内置 eSIM，`is_support_psim=0`，无物理插卡座） |
| `trustos_a` AVB 校验指令典型偏移 | `0x981ec`（由 `inspect_backup.py` 经 ARM64 `ADRP+ADD` 与函数尾扫描动态定位） |

> **B15 实机验证边界与已发现限制（`PARTIAL`）**：
> - 上游工程已在一台 `B15`（`board_id=1`）实机上实际安装过双系统并完成：全分区读回校验写入 `_b`、Android `_a` (`Magisk 28103` + `UFI-TOOLS v4.0.0` `:2333`/`ttyd :1146` + `charging,adb`)、以及 `_b <-> _a <-> _b` 双向切槽与物理 5 秒按键守护验证（`final-roundtrip-verify.json`）；
> - 但请注意：**在 `B15` OpenWrt 终检快照中，`wan.up=0`、`ip4/ip6=null`、`net_red=1`、`imeis=[null, null]`**——该台机器在 OpenWrt 下两张内置 eSIM 虽报告 `ready`，但 **5G eSIM 数据拨号在审计当时并未上线，尚未获得 OpenWrt eSIM 实网连通实证**，且当时底包 `aic8800` / modem XML 复用自 `B28` 提取物；同时本仓库新重构的 `kit.py` CLI 尚未实机运行。

## 2. 常见硬件特性与灯效判定（重要排查参考）

1. **红灯误判排查（Signal Red vs 没网）**：
   - 在内置双 eSIM 机型上，若当前激活槽位仅启用了其中一张已实名/有资费的 eSIM（另一张未开卡/未实名 `CFUN` 未注册），或当 `u30-modemd` 所在活跃 SIM 卡处于网络注册异常（例如 `stat=8` 仅紧急呼叫 / 未开通流量），信号 LED 会亮**红灯**。
   - 排查方法（SSH 连入 `192.168.77.1` 后执行只读诊断）：
     ```sh
     ubus call mu300.dash status '{"slot":0}'
     mu300-physical-sim status
     ```
     若两张内置 eSIM 中一张有效一张未实名，在 LuCI 首页切卡（或配置短按物理键切卡）到已激活的 eSIM 即可正常上网与转绿/蓝灯。
2. **Wi-Fi 灯不亮原因（本套件已自动修复）**：
   - 通用底包默认 `unisoc_modem.main.wifi_device='wlan0'`，而 6.12 内核 `aic8800` 驱动实际 AP 接口名为 **`phy0-ap0`**。
   - `provision_openwrt.py` 会自动设置 `wifi_device='phy0-ap0'` 并重启 `/etc/init.d/f50pro-leds`，使 5 GHz Wi-Fi 开启后白色指示灯正常点亮。
3. **2 GiB 存储显示与扩容原因**：
   - F50 Pro 分区表中专用于双系统 Linux 根文件系统的 `fulldumpdb` 分区物理容量恒为 **`2 GiB` (`2,147,483,648` B)**；
   - 原生纯 ext4 底包构建体积仅约 `240–300 MiB`（为了缩小刷机文件体积与写入时间），因此刚刷完若不执行在线 ext4 resize（`f50pro-rootfs-grow.py`），`df -h /` 只会显示约几百 MB 而非完整的 `2 GiB`。本套件在首次连网配好系统时自动执行安全的内核在线扩容（`EXT4_IOC_RESIZE_FS`），无损撑满 `fulldumpdb` 的 `2 GiB` 容量。

## 3. 一键刷机与双系统部署

与插卡版完全共用一套脚本（仅内核层面通过 `board_id=1` 走内置双 eSIM 通道，无需特殊参数）：

```powershell
# 推荐：Profile 3 双系统全功能（Android Root + UFI-TOOLS <-> OpenWrt 25.12.5 双向 5s 切换）
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\b15-session `
  --webui-password "<WEBUI_PASSWORD>" `
  --generate-password
```

确认干跑计划 `flash_plan.json` 后附加 `--execute` 完成刷入与配置。
