# 故障排查、下载协议边界 (`SPRD4:AutoD` vs `SPRD3`) 与宿主网络安全说明

## 1. 下载模式真相：`SPRD4:AutoD`（依赖正常 SPL/U-Boot）vs 裸机 `SPRD3` BootROM

> **重要工程安全披露（请勿混淆）**：本仓库默认调用的 `spd_dump --kickto 2` 运行在 **`SPRD4:AutoD`**（U-Boot `autodloader`）模式，**并非芯片底层不可变 Mask `SPRD3` BootROM**：

| 对比项 | `SPRD4:AutoD`（本工具链当前通路） | `SPRD3` 裸机 BootROM（真死砖救砖必须通路） |
| :--- | :--- | :--- |
| **设备端运行前提** | 闪存上现有的 **`splloader` + `uboot_<slot>` 必须完好并能初始化 USB `boot_diag`** | 即使 `SPL`/`U-Boot` 彻底损坏仍可在硬件层枚举 `1782:4D00` |
| **`spd_dump` 行为** | 握手回报 `BSL_REP_VER: "SPRD4:AutoD"` 后自动跳过外部 `fdl1`/`fdl2` 上传 | 必须先上传与 **Unisoc `UMS9632`（`0x65008000` / `0xbdfffe00`）** 完全匹配且通过 BootROM 验签的 `FDL1` + `FDL2` |
| **当 `U-Boot` 或 `SPL` 损坏时** | **`AutoD` 不可用**；`SPL` 反汇编证实其**无 `uboot` 自动切槽回退逻辑**（一旦活动槽 `uboot` 验签失败，报错 `0x4e` 并进入死循环） | 唯一理论救砖出口（需冷上电短窗或硬件触点触发 `SPRD3` + 外部已签名 `UMS9632` `FDL1/FDL2`） |
| **本仓库支持现状** | **`VERIFIED`（上游 8/8 次实机成功连机路径）**；注意 `r all` 不主动备份 `eMMC boot1` (`splloader_bak`) | **`BLOCKED / NOT INCLUDED`（上游 0/18 次成功实证；本仓库不含官方 `.pac` 或 `UMS9632` 签名 `FDL1/FDL2`）** |

### Windows WinUSB 驱动安装要点
- 当 `spd_dump` 提示 `Waiting for boot_diag` 或缺少 `1782:4D00` / `1782:4D03` 驱动时，在 `v1.1.0` 中可直接运行 `qmk_driver_installer\install_connected_drivers.bat`（已修复指向 `unisoc_drivers.txt`）或 `install_unisoc_drivers.bat`（管理员运行）：
  ```powershell
  .\build\runtime-tools\host-tools-win64\qmk_driver_installer\qmk_driver_installer.exe --force `
    .\build\runtime-tools\host-tools-win64\qmk_driver_installer\unisoc_drivers.txt
  ```
- **旧版 `v1.0.0` 注意**：若使用的是 `v1.0.0` 旧压缩包，其中的 `install_connected_drivers.bat` 默认读取 `drivers.txt`（不含 `1782:4D00`），请显式指定 `unisoc_drivers.txt` 或改用 Zadig。
- **Linux / macOS / Android Termux 主控说明**：详见 [docs/multi-platform-host.md](multi-platform-host.md)（Linux `udev` 规则、macOS `sudo` 权限与 Android Termux `--spd-mode su` vs `--usb-fd` 边界）。

---

## 2. 宿主机多平台网卡防劫持 (`host_network.py`)

每次插上刷好 OpenWrt 的 F50 Pro（`VID_1D6B&PID_0104` RNDIS / CDC-NCM + ACM）或带 `rndis` 的 Android 时，宿主机默认可能尝试 DHCP 获取并将设备当成主互联网网关，导致本机电脑原本的宽带/Wi-Fi 网络断网。

本工具包内置跨平台 [host_network.py](../scripts/host_network.py)，提供自动隔离与路由审计（`provision-openwrt` 默认自动生效，也可手动单独执行 `audit` / `isolate`）：
- **Windows (`win64`)**：清理负向 `UsbFlags` 缓存、调用 `setupapi`/`newdev` 绑定微软自带 `netrndis.inf` RNDIS6，并将 `UsbNcm` / `RNDIS` 固定为 `192.168.77.12/24` 无默认网关无 DNS、关闭 IPv6。
- **Linux (`linux-x64` / `linux-arm64`)**：识别 `1d6b:0104` / `cdc_ncm` / `rndis_host` 网卡，优先调用 `nmcli`（`ipv4.never-default yes`, `ipv6.method disabled`）或 `ip route del default dev <iface>` 隔离为 `192.168.77.12/24`。
- **macOS (`macos`)**：通过 `networksetup -setmanual <service> 192.168.77.12 255.255.255.0 ""` 清空路由与 DNS、关闭 IPv6，并用 `netstat -rn` 审计默认路由无泄露。
- **Android Termux (`android-arm64`)**：只读审计路由表，提示关闭手机多余数据冲突或使用 Wi-Fi AP 连接管理口。

手动运行网络修复与审计：

```powershell
.\.venv\Scripts\python.exe scripts\host_network.py bind-rndis
.\.venv\Scripts\python.exe scripts\host_network.py isolate --snapshot build\device-session\build\host_network_snapshot.json
.\.venv\Scripts\python.exe scripts\host_network.py audit
# 需要恢复隔离前的原始网卡配置时：
.\.venv\Scripts\python.exe scripts\host_network.py restore --snapshot build\device-session\build\host_network_snapshot.json
```

---

## 3. 可用恢复路径与明确限制（Rollback Boundaries）

**前提边界**：以下恢复命令**仅在设备仍可进入 `SPRD4:AutoD`（即活动槽位 `splloader` 与 `uboot` 尚能启动，或尚能进入 OpenWrt/Android）时成立**。若因外部误写破坏了 `splloader` 或活动槽 `uboot` 导致 `U-Boot` 无法加载，则无法仅凭本工具包内 `spd_dump --kickto 2` 完成裸机 `SPRD3` 救砖（必须另备外部 `UMS9632` 签名 `FDL1`/`FDL2` 或官方 `.pac`）。

正因如此，本工具包强制执行：
- `FORBIDDEN_PARTITIONS` 永久封锁 `splloader`、`prodnv`、`calinv`、NV/校准分区、`super`、`userdata`；
- 刷写槽位 `_b` 同步 `uboot_b <- uboot_a` 时，强制在切换 `misc+2048` 活动槽位**之前**完成全量 SHA-256 读回核验。

### 场景 A：卡在槽位 `_b`，想切回槽位 `_a`
- 方法 1：OpenWrt 正常运行时长按机身实体键 5 秒，或 SSH 执行 `/opt/mu300/bin/mu300-next-boot android && reboot`。
- 方法 2：将设备切入 `SPRD4` 下载模式，写回本机原始 `misc` 引导块（构建目录下已预生成 `stage3\misc_rollback_a.bin`）：
  ```powershell
  .\build\runtime-tools\host-tools-win64\spd_dump_251\spd_dump.exe --wait 120 --kickto 2 `
    wof misc 2048 build\my-device\build\stage3\misc_rollback_a.bin reset
  ```

### 场景 B：完整还原到刷机前出厂状态
从备份目录写回已修改过的系统槽分区（切勿覆盖 NV/射频/校准分区）：
```powershell
# 示例：还原 _a 与 _b 引导区与 misc（保持 prodnv/calinv/persist/NV 分区不动）
spd_dump --wait 120 --kickto 2 `
  w trustos_a backup\trustos_a `
  w init_boot_a backup\init_boot_a `
  w trustos_b backup\trustos_b `
  w boot_b backup\boot_b `
  w vendor_boot_b backup\vendor_boot_b `
  w_force init_boot_b backup\init_boot_b `
  wof misc 2048 build\my-device\build\stage3\misc_rollback_a.bin `
  reset
```
