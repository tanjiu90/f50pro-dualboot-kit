# F50 Pro 内置双 eSIM 版 (`board_id=1` / `B15`) 开发与刷机说明

## 1. 硬件识别与差异摘要

| 项目 | 参数 |
| :--- | :--- |
| 设备平台 | ZTE `MU3356` / Unisoc `UMS9632` (`arm64`) |
| 出厂系统 | Android 15 (`SDK 35`, `vendor_boot` hardware `ums9632_1h10_mbb`) |
| Board ID (`/proc/driver/board_id`) | `1` |
| SIM 拓扑 | **纯内置双 eSIM**（出厂多为移动 + 电信内置 eSIM，`is_support_psim=0`，无物理插卡座） |
| `trustos_a` AVB 校验指令典型偏移 | `0x981ec`（由 `inspect_backup.py` 经 64B 指纹动态定位） |

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
