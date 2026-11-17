# 多平台主控端部署指南 (Windows / Linux / macOS / Android Termux OTG)

本工具包支持在 **4 类宿主机平台**上作为主控端对 **ZTE F50 Pro (`MU3356` / `UMS9632`)** 执行只读 BROM 备份、离线镜像构建、双系统刷写、配网与 E2E 校验，并支持按需**自主选择下载内容**（只下当前操作系统工具包、只下目标配置所需固件包）。

> **诚实边界说明**：
> - `Windows x64` 与上游同源方案具有实机刷机历史验证（`B28` 完整通过、`B15` 部分通过）；
> - `Linux x86_64` 与 `macOS Universal` 已接入 GitHub Actions 真实系统自动化测试矩阵（Python 工具链 + `bootstrap.sh` + `preflight` + 二进制存在与哈希校验）；但**本仓库尚未在真实 Linux / macOS / Android OTG 物理硬件连接 F50 Pro 上完成实机全流程刷写闭环**，首次使用请严格停在 Dry-Run 门禁确认后再 `--execute`。

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
2. **一键引导与按需下载**：
   ```bash
   git clone https://github.com/tanjiu90/f50pro-dualboot-kit.git
   cd f50pro-dualboot-kit
   bash scripts/bootstrap.sh            # 自动识别 linux-x64 或 linux-arm64
   ```
3. **安装 USB udev 规则（免 sudo 访问 `1782:4d00` 与 OpenWrt `1d6b:0104`）**：
   ```bash
   sudo cp assets/udev/99-unisoc-f50pro.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules && sudo udevadm trigger
   ```
   *(若暂不安装 udev 规则，也可在 `backup` / `flash` 时传递 `--spd-mode sudo`)*
4. **预检与执行**：
   ```bash
   .venv/bin/python scripts/kit.py preflight
   .venv/bin/python scripts/kit.py auto --profile 3-dual-full --work-dir build/my-device --webui-password "<PW>" --generate-password --openclash
   ```
5. **Linux 网卡防劫持 (`host_network.py`)**：OpenWrt 启动并枚举 CDC-NCM / RNDIS 时，`host_network.py` 会通过 `nmcli`（若使用 NetworkManager）或 `ip route del default dev <iface>` 将其隔离为纯 `192.168.77.12/24` 管理网段，禁止 `0.0.0.0/0` 抢占宿主机外网。

---

## 3. macOS (Apple Silicon M 系列 / Intel Universal) 部署步骤

1. **前置依赖**：系统需有 Python 3.11+（`brew install python@3.11` 或 Xcode Command Line Tools 自带 Python3；`bin/spd_dump` 与 `platform-tools/adb` 均已自带原生 **Universal arm64 + x86_64** 通用二进制）。
2. **一键引导与按需下载**：
   ```bash
   git clone https://github.com/tanjiu90/f50pro-dualboot-kit.git
   cd f50pro-dualboot-kit
   bash scripts/bootstrap.sh --platform macos
   ```
   *(若通过浏览器手动下载而非 curl，首次执行前运行 `xattr -dr com.apple.quarantine build/runtime-tools/host-tools-macos` 清除隔离属性)*
3. **USB 权限与运行方式**：
   macOS 对原生 `libusb` 独占声明 `1782:4D00` 设备需要 `root` 权限：
   ```bash
   # 先免特权运行 preflight / inspect / build：
   .venv/bin/python scripts/kit.py preflight

   # 涉及 USB BootROM 读写（backup / flash）或 networksetup 配网隔离时使用 sudo：
   sudo .venv/bin/python scripts/kit.py auto \
     --profile 3-dual-full \
     --work-dir build/my-device \
     --webui-password "<PW>" \
     --generate-password \
     --openclash
   ```
4. **macOS 网络服务隔离**：OpenWrt 首启枚举 `CDC NCM` / `RNDIS` 时，macOS 可能将其加入系统网络服务并赋予默认网关。`host_network.py` 会调用 `networksetup` 对该 USB 服务设置静态 IP `192.168.77.12`、空网关 (`""`)、清空 DNS 并关闭 IPv6。

---

## 4. Android 手机 / 平板 OTG 主控部署 (Termux)

> **关键底层技术差异（请务必先读懂 Root 与非 Root 的真实区别）**：
> `spreadtrum_flash` (`spd_dump.c`) 在非 Root Android 下依赖 `termux-usb --usb-fd <fd>` 注入已授权的单个 USB 文件描述符，**源码级禁用了 libusb 热插拔扫描 (`LIBUSB_OPTION_NO_DEVICE_DISCOVERY`) 与 `--kickto 2` 自动跨状态重连**。

| Android 宿主模式 | 使用二进制 | 自动 `--kickto 2` 抓取冷启动 | BROM 全流程支持 | ADB 配网方案 |
| :--- | :--- | :---: | :---: | :--- |
| **Rooted Android (Magisk / KernelSU / APatch)** | `bin/spd_dump-su` (静态 Linux `arm64` musl v251) | **支持**（`su` 直通 `/dev/bus/usb` + Netlink 热插拔） | 完整（使用 `--spd-mode su`） | USB OTG (`adb`) 或无线 (`192.168.0.1:5555`) |
| **Non-Root Android (原生 Termux + Termux:API)** | `bin/spd_dump-termux-usb` (NDK `__ANDROID__` `--usb-fd`) | **不支持**（设备需**事先处于 `1782:4d00` `autodloader` 模式**并已完成 USB 弹窗授权） | **实验性 (`EXPERIMENTAL`)**（`--spd-mode termux-usb`） | `termux-adb` (`nohajc/termux-adb`) 或 `--adb-serial 192.168.0.1:5555` |

### Termux 初始化命令
```bash
# 1. 从 F-Droid 安装 Termux 与 Termux:API（切勿使用 Google Play 旧版，两者签名不兼容）
pkg update && pkg upgrade -y
pkg install -y git python python-cryptography python-pip clang rust libffi openssl android-tools termux-api openssh

# 2. 克隆并部署（仅下载 android-arm64 工具链及所需固件包）
git clone https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
bash scripts/bootstrap.sh --platform android-arm64

# 3A. Rooted 安卓手机（推荐）：全自动抓取 + 刷写
.venv/bin/python scripts/kit.py auto \
  --profile 3-dual-full \
  --spd-mode su \
  --work-dir build/my-device \
  --webui-password "<PW>" \
  --generate-password \
  --openclash

# 3B. 无 Root 安卓手机（实验性）：先让 F50 Pro 处于 1782:4d00 autodloader 并用 termux-usb -r 授权
termux-usb -l
termux-usb -r /dev/bus/usb/001/002
.venv/bin/python scripts/kit.py backup \
  --spd-mode termux-usb \
  --usb-dev /dev/bus/usb/001/002 \
  --output-dir build/my-device/backup

# 无 Root 场景下的 Android 槽位配网（OTG termux-adb 或 Wi-Fi 无线 ADB）：
.venv/bin/python scripts/kit.py provision-android \
  --plan build/my-device/build/flash_plan.json \
  --adb-serial 192.168.0.1:5555
```
