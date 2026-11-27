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
- 当 `spd_dump` 提示 `Waiting for boot_diag` 或缺少 `1782:4D00` / `1782:4D03` 驱动时，在**管理员 PowerShell** 中直接运行 `.\scripts\install_unisoc_drivers.bat`（或在 `v1.1.2+` 中运行自动补全了 `--all` 的 `qmk_driver_installer\install_unisoc_drivers.bat`）；手动命令**必须带 `--all`** 才能在设备未进入下载模式时离线预装：
  ```powershell
  .\build\runtime-tools\host-tools-win64\qmk_driver_installer\qmk_driver_installer.exe --force --all `
    .\build\runtime-tools\host-tools-win64\qmk_driver_installer\unisoc_drivers.txt
  ```
- **旧版 `v1.0.0` / `v1.1.0` / `v1.1.1` 注意**：若使用的是旧版包内未带 `--all` 的 `.bat`，在设备未处于 `1782:4D00` BROM 模式时会输出 `No matching device found` 且不会安装驱动；请显式补加 `--force --all unisoc_drivers.txt` 或改用 Zadig。
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
- 方法 2（推荐受控回退）：在同一个 `SPRD4` 会话内自动校验本机备份、GPT、设备身份、写前槽位状态与写后读回 SHA-256，校验通过才发送重启；务必将步骤 1 干跑输出的 `plan_sha256` 和 `rollback_sha256` 传入执行命令：
  ```powershell
  # 1. 先离线干跑核对本机指纹、plan_sha256 与 rollback_sha256：
  .\.venv\Scripts\python.exe scripts\kit.py rollback-a --plan build\my-device\build\flash_plan.json
  # 2. 确认无误后绑定上述两项摘要执行受控回退：
  .\.venv\Scripts\python.exe scripts\kit.py rollback-a `
    --plan build\my-device\build\flash_plan.json `
    --expected-plan-sha256 "<步骤1输出的plan_sha256>" `
    --expected-rollback-sha256 "<步骤1输出的rollback_sha256>" `
    --execute
  ```

### 场景 B：完整还原到刷机前出厂状态（必须以已执行计划派生清单并遵循受控门禁）
**重要说明**：完整出厂还原必须**从本次刷机的 `flash_plan.json` 派生全部已修改分区清单**——除 `trustos_a`、`init_boot_a`、`trustos_b`、`boot_b`、`vendor_boot_b`、`init_boot_b`、`fulldumpdb` 与 `misc+2048` 外，**还包含 `BSP_SYNC_PAIRS_F50PRO` 同步过的全部 `_b` 槽 BSP 目标分区（`sml_b`、`teecfg_b`、`uboot_b`、`l_fixnv2` 等，详见 `flash_plan.json["operations"]`）**；同时严禁触碰 `FORBIDDEN_PARTITIONS` 中的 `splloader`/`prodnv`/`calinv`/`ztecfg`/`persist`/NV 校准分区。**切勿在未核验备份、GPT、本机身份（`ztecfg`/`persist` 哈希）、写前基线与逐分区读回 SHA-256 的情况下执行裸 `spd_dump w ... reset`！**

安全执行顺序：
1. **先切回并验证原厂安卓 `_a`**：优先使用受控命令 `kit.py rollback-a --plan ... --expected-plan-sha256 ... --expected-rollback-sha256 ... --execute`（在同一 `SPRD4` 会话内完成 GPT、本机身份、写前槽位状态与读回校验后重启，并确认原厂安卓 `19D2:0246` 与 `http://192.168.0.1:8080` 恢复在线）。
2. **校验本地全量原厂备份完整性**：运行 `.\.venv\Scripts\python.exe scripts\kit.py backup --output-dir <你的备份目录> --verify-only`，确认 `checks_passed=true` 且 `backup_coverage.flashed_targets_and_boot_slots_covered=true`（所有修改目标分区、BSP 分区与 `fulldumpdb` 均在 `SHA256SUMS.txt` 中完好无损）。
3. **仅在需要彻底清空 `_b` 槽 OpenWrt 与恢复原厂 BSP + `fulldumpdb` 时**：从 `flash_plan.json["operations"]` 读取实际改动过的所有目标分区清单；在同一 `SPRD4:AutoD` 交互会话内先核对 `partition_list` 与本机 `ztecfg` / `persist` 身份哈希（与 `device_identity.unit_identity_partitions` 一致），再按写前校验 -> 写回对应原厂备份（含全部 BSP `_b` 目标与 `fulldumpdb`）-> 逐分区读回比对 SHA-256 的顺序执行，全部字节一致后再执行 `reset`；任一分区读回不一致时立即中止，绝不盲目重启。
