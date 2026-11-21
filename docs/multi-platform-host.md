# 多平台主控端部署指南 (Windows / Linux / macOS / Android Termux OTG)

本工具包支持在 **4 类宿主机平台**上作为主控端对 **ZTE F50 Pro (`MU3356` / `UMS9632`)** 执行只读 BROM 备份、离线镜像构建、双系统刷写、配网与 E2E 校验，并支持按需**自主选择下载内容**（只下当前操作系统工具包、只下目标配置所需固件包）。

> **诚实边界说明（严格分层，绝不混同）**：
> - **`Windows x64`**：上游同源方案具有 `B28` 实机全链路验证（`82` 文件全量备份 + 双系统 + `5G NR SA` + Wi-Fi 6 + OpenClash + 物理键双向切换）；`B15`（内置双 eSIM）按用户决策跳过付费 eSIM 蜂窝联网测试（非发布阻断项）。本仓库 CLI 自身尚待真机试点实测。
> - **`Linux x86_64` & `macOS Universal`**：已通过 GitHub Actions 真实宿主机 CI（`pytest` 故障注入 + `bootstrap.sh` + `preflight --strict` + 离线 `plan` + 二进制存在与哈希校验），但**尚未在物理 Linux / macOS 上插接 F50 Pro 完成实机 USB 通信或端到端刷写**。
> - **`Linux ARM64 (aarch64)`**：交叉编译静态 musl 二进制已打包验证，但 GitHub Actions `[ubuntu-latest, macos-latest, windows-latest]` **未覆盖真实 ARM64 Linux Runner**，且依赖发行版提供 `android-tools-adb`。
> - **`Android Termux OTG`**：Rooted (`--spd-mode su`) 具备 `--kickto 2`；**无 Root (`--usb-fd`) 为单次授权句柄，设备重启/重置即失效且源码禁用热插拔发现，因此属于 `EXPERIMENTAL` 分段手操，不是一键闭环刷机方案**。
> - **校验声明**：`release-manifest.json` 提供针对本仓库清单的 **SHA-256 完整性校验**，**不构成** GPG / Cosign 等密码学发布者签名。生产执行请始终固定 **Release Tag 或 Commit SHA**，切勿直接拉取可变 `main`。

---

## 1. 按需自主选择下载 (`v1.1.0`)

不必下载全量 150+ MB 资源包；可通过以下 **3 种方式**任意组合下载：

### 方式 A：交互式终端菜单
```bash
# Linux / macOS / Android Termux
bash scripts/bootstrap.sh --interactive

# Windows PowerShell
.\scripts\bootstrap.ps1 -Interactive
```

### 方式 B：命令行精确筛选（按主机 OS + 按刷机配置）
```bash
# 仅看可下载包清单、大小、SHA-256 与直链（不下载任何文件）
python3 scripts/kit.py fetch-assets --list-packs

# 示例 1：Linux x86_64 主机，仅刷「配置 1：纯安卓 Root + UFI-TOOLS」（跳过 OpenWrt 与 OpenClash，节省 ~62 MiB）
bash scripts/bootstrap.sh --platform linux-x64 --profile 1-android-ufi

# 示例 2：macOS 主机，仅刷「配置 2：原厂安卓 + OpenWrt + OpenClash」（跳过 Android APK 包，节省 ~30 MiB）
bash scripts/bootstrap.sh --platform macos --profile 2-dual-stock-openwrt

# 示例 3：Linux ARM64 路由器/开发板主控，仅下工具链不含 OpenClash
bash scripts/bootstrap.sh --platform linux-arm64 --profile 3-dual-full --no-openclash

# 示例 4：精准指定任意 Release 包名（例如离线镜像站/U 盘多系统打包）
python3 scripts/kit.py fetch-assets --packs host_tools_macos host_tools_linux_x64 openwrt_base
```

### 方式 C：Release 页面手动勾选下载放入 `bundle-cache/`
从 GitHub Releases 页面按需下载对应 `.zip` / `.tar.gz` / `.tar.xz` 文件，放到仓库根目录 `bundle-cache/` 后执行 `python3 scripts/kit.py fetch-assets`（离线本地自动校验 SHA-256 并解压到 `build/runtime-tools/`，无需重新联网）。

---

## 2. Linux (`x86_64` / `aarch64`) 部署步骤

1. **安装 Python 3.10+ 与系统工具**（ARM64 需额外装系统 `adb`，因 Google 官方仅提供 x86_64 `platform-tools`）：
   ```bash
   # Debian / Ubuntu / Armbian
   sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip
   # 仅 Linux ARM64 需执行：
   sudo apt-get install -y android-tools-adb
   ```
2. **一键引导与按需下载（默认克隆 `main` 最新修复版；如需固定版本可加 `--branch <tag>`）**：
   ```bash
   git clone --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
   cd f50pro-dualboot-kit
   bash scripts/bootstrap.sh            # 自动识别 linux-x64 或 linux-arm64
   ```
3. **安装 USB udev 规则（推荐最小权限：免全进程 root 访问 `1782:4d00` 与 `1d6b:0104`）**：
   ```bash
   sudo cp assets/udev/99-unisoc-f50pro.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules && sudo udevadm trigger
   ```
   *(若暂不安装 udev 规则，请用普通用户跑 `preflight` / `plan`，仅在需要时传递 `--spd-mode sudo` 限定提权范围，避免整套 Python 以 root 运行)*
4. **严格预检、显式授权备份与离线计划**：
   ```bash
   .venv/bin/python scripts/kit.py preflight --strict --operation backup
   .venv/bin/python scripts/kit.py backup --output-dir build/my-device/backup --authorize-device-reboot --webui-password "<PW>"
   .venv/bin/python scripts/kit.py plan --profile 3-dual-full --work-dir build/my-device --openclash
   ```
5. **Linux 精确网卡隔离 (`host_network.py`)**：通过 `/sys/class/net/<iface>/device/../../idVendor` + `idProduct` 仅匹配真实 F50 Pro USB 接口 (`1D6B:0104`，保留现行工作态 `ncm` / `ecm` / `rndis`；绝不误改手机 USB 共享网络、USB-C 扩展坞或普通 `192.168.0.1` Wi-Fi)，并记录快照支持无损恢复。

---

## 3. macOS (Apple Silicon M 系列 / Intel Universal) 部署步骤

1. **前置依赖**：系统需有 Python 3.11+（`brew install python@3.11` 或 Xcode Command Line Tools 自带 Python3；`bin/spd_dump` 与 `platform-tools/adb` 均已自带原生 **Universal arm64 + x86_64** 通用二进制）。
2. **一键引导与按需下载（默认克隆 `main` 最新修复版；如需固定版本可加 `--branch <tag>`）**：
   ```bash
   git clone --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
   cd f50pro-dualboot-kit
   bash scripts/bootstrap.sh --platform macos
   ```
   *(若通过浏览器手动下载而非 curl，首次执行前运行 `xattr -dr com.apple.quarantine build/runtime-tools/host-tools-macos` 清除隔离属性)*
3. **USB 权限与运行方式**：
   macOS 对原生 `libusb` 独占声明 `1782:4D00` 设备需要 `root` 权限；所有离线构建、严格预检和 `plan` 应在**无特权普通用户**下完成：
   ```bash
   # 先免特权运行 preflight 与 100% 离线 plan：
   .venv/bin/python scripts/kit.py preflight --strict --operation backup
   .venv/bin/python scripts/kit.py plan --profile 3-dual-full --work-dir build/my-device --openclash

   # 仅在物理 BROM 备份（--authorize-device-reboot）或实机 --execute 时限定最小权限：
   .venv/bin/python scripts/kit.py backup --output-dir build/my-device/backup --spd-mode sudo --authorize-device-reboot --webui-password "<PW>"
   ```
4. **macOS 网络服务精准关联与隔离**：`host_network.py` 通过 `networksetup -listnetworkserviceorder` 严格分离 `Hardware Port`、`BSD Device` 与用户重命名的 `Network Service` 并结合 `system_profiler SPUSBDataType` 校验 VID/PID，仅隔离真实 F50 Pro USB 接口 (`management` 模式配置 `192.168.77.12` 空网关，`internet-exit` 模式可放行路由)，并在多设备或用户自定义配置下拒绝盲目覆盖。

---

## 4. Android 手机 / 平板 OTG 主控部署 (Termux)

> **关键底层技术差异（请务必先读懂 Root 与非 Root 的真实边界）**：
> `spreadtrum_flash` (`spd_dump.c`) 在非 Root Android 下依赖 `termux-usb --usb-fd <fd>` 注入**单次授权文件描述符**，**源码级禁用了 libusb 热插拔扫描 (`LIBUSB_OPTION_NO_DEVICE_DISCOVERY`) 与 `--kickto 2` 自动跨状态重连**；**设备一旦重启、reset 或重枚举，现有 fd 立即失效**。因此，**无 Root Termux 不是“全自动一键闭环刷机方案”**，仅作为已进 `1782:4d00` 模式后的 `EXPERIMENTAL` 分阶段手动工具。

| Android 宿主模式 | 使用二进制 | 自动 `--kickto 2` 抓取冷启动 | BROM 全流程支持 | ADB 配网方案 |
| :--- | :--- | :---: | :---: | :--- |
| **Rooted Android (Magisk / KernelSU / APatch)** | `bin/spd_dump-su` (静态 Linux `arm64` musl v251) | **支持**（`su` 直通 `/dev/bus/usb` + Netlink 热插拔） | 完整（使用 `--spd-mode su`） | USB OTG (`adb`) 或无线 (`192.168.0.1:5555`) |
| **Non-Root Android (原生 Termux + Termux:API)** | `bin/spd_dump-termux-usb` (NDK `__ANDROID__` `--usb-fd`) | **不支持**（设备需**事先处于 `1782:4d00` `autodloader` 模式**并已完成 USB 弹窗授权） | **实验性 (`EXPERIMENTAL`)**（`--spd-mode termux-usb`） | `termux-adb` (`nohajc/termux-adb`) 或 `--adb-serial 192.168.0.1:5555` |

### Termux 初始化命令
```bash
# 1. 从 F-Droid 安装 Termux 与 Termux:API（切勿使用 Google Play 旧版，两者签名不兼容）
pkg update && pkg upgrade -y
pkg install -y git python python-cryptography python-pip clang rust libffi openssl android-tools termux-api openssh

# 2. 克隆最新 main 并部署（如需固定版本可加 --branch <tag>；仅下载 android-arm64 工具链及所需固件包）
git clone --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
bash scripts/bootstrap.sh --platform android-arm64

# 3A. Rooted 安卓手机（推荐）：先跑 offline plan 审阅，再用 --spd-mode su --authorize-device-reboot 执行
.venv/bin/python scripts/kit.py backup --spd-mode su --authorize-device-reboot --output-dir build/my-device/backup --webui-password "<PW>"
.venv/bin/python scripts/kit.py plan --profile 3-dual-full --work-dir build/my-device --openclash

# 3B. 无 Root 安卓手机（EXPERIMENTAL，非一键闭环）：每次重枚举都要重新用 termux-usb -r 授权新 fd
termux-usb -l
termux-usb -r /dev/bus/usb/001/002
.venv/bin/python scripts/kit.py backup \
  --spd-mode termux-usb \
  --authorize-device-reboot \
  --usb-dev /dev/bus/usb/001/002 \
  --output-dir build/my-device/backup

# 无 Root 场景下的 Android 槽位配网（OTG termux-adb 或 Wi-Fi 无线 ADB）：
.venv/bin/python scripts/kit.py provision-android \
  --plan build/my-device/build/flash_plan.json \
  --adb-serial 192.168.0.1:5555
```
