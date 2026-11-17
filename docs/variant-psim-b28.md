# F50 Pro 插卡版 (`board_id=6` / `B28`) 开发与刷机说明

## 1. 硬件识别与差异摘要

| 项目 | 参数 |
| :--- | :--- |
| 设备平台 | ZTE `MU3356` / Unisoc `UMS9632` (`arm64`) |
| 出厂系统 | Android 15 (`SDK 35`, `vendor_boot` hardware `ums9632_1h10_mbb`) |
| Board ID (`/proc/driver/board_id`) | `6` |
| SIM 拓扑 | **外置 Nano-SIM 卡槽 + 内置 eSIM 芯片 (`sim_slots=2`, mux 切换)** |
| `trustos_a` AVB 校验指令典型偏移 | `0x9856c`（由 `inspect_backup.py` 经 ARM64 `ADRP+ADD` 与函数尾扫描动态定位，不写死） |

## 2. SIM 多路复用（`f50pro-card.sh` 补丁）

上游通用 rootfs 原生识别 `board_id` `0..5`；插卡版实机为 `board_id=6`，必须应用 [f50pro-board6.patch](../assets/openwrt-patch/f50pro-board6.patch)：
- 将 `6` 加入 `f50pro_detected_board_id` 与 `f50pro_board_override` 允许列表；
- 物理通道集合映射为 `'1 2 3 4'`：
  - `6:1` -> `1 chip_select 1`（内置 eSIM 通道 1）
  - `6:2` -> `0 psim_select 1`（外置物理 Nano-SIM 主卡通道）
  - `6:3` -> `0 psim_select 0`（外置物理 Nano-SIM 备选路由）
  - `6:4` -> `1 chip_select 0`（内置 eSIM 通道 2）
- 内核驱动参数通过 `vendor_boot_b` 的内核 `cmdline` 注入：`u30pro_sim_mux.layout=mu3356`（由 `build_images.py` 严格验证本机 DTB SHA-256 后附加）。

> **实机验证口径说明**：上游工程已基于实机 `B28` 完整验证过 OpenWrt `_b`（含外置 Nano-SIM `CT 46011` 5G NR SA 上网）、Android `_a` (`Magisk 28103` + `UFI-TOOLS`) 及物理 5 秒双向切换（`VERIFIED`）；本独立仓库封装后的 `kit.py` CLI 目前已通过离线单测与安全校验，尚未在实机重跑一轮在线刷写（`UNVERIFIED` live CLI）。

`provision_openwrt.py` 会自动核对 `/opt/mu300/lib/f50pro-card.sh` 的 SHA-256（已合入或待打补丁），并验证合入后哈希 `d283d5a7388d05cae7f2645e6bf9a9f5a7ddee5d09c12a5e69d6f5c56663af47`。

## 3. 刷机与配置流程

支持全部 3 种配置（推荐 `3-dual-full`）：

```powershell
# 完整双系统 + 双向 5 秒按键切换 + 2 GiB 存储 + Wi-Fi 指示灯修复
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\b28-session `
  --webui-password "<WEBUI_PASSWORD>" `
  --generate-password
```

检查 `build\b28-session\build\flash_plan.json` 并确认后加 `--execute` 执行。

## 4. 使用与指示灯状态说明

- **Wi-Fi 灯不亮常见原因（已在本套件自动修复）**：`unisoc_modem.main.wifi_device` 必须为 `phy0-ap0` 而非旧版 `wlan0`，且启用 `/etc/init.d/f50pro-leds`。
- **OpenWrt 分区容量**：全量镜像写入 `fulldumpdb`（`2 GiB`）后，`f50pro-rootfs-grow.py` 在线扩容 ext4 至完整 `2147483648` 字节，并修复 LuCI 首页系统容量/物理容量展示。
- **双系统切换（Profile 3）**：任意系统运行期间长按机身实体键 **5 秒**（`>5000ms`），蓝灯/绿灯闪烁确认后自动原子更新 `misc+2048` (`BCAB`) 并重启进入另一系统。
