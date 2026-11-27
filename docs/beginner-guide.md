# 中兴 F50 Pro (MU3356) 双系统工具包 · 零基础小白保姆级使用教程

> **适用工具版本**：`f50pro-dualboot-kit v1.1.3`
>
> **适用机型**：**中兴 F50 Pro（型号 `MU3356` / 展锐 `UMS9632` / 出厂 Android 15）**
>
> 涵盖 **插卡版（`board_id=6` / `B28`）** 与 **内置双 eSIM 版（`board_id=1` / `B15`）**。

> ### 🌟 Windows 零基础最简方式（推荐：绿色图形一键刷机助手，免装 Python / Git！）
>
> 如果你不想敲任何命令行、也不想折腾 Python 和 Git：
> 1. 打开 GitHub Releases 最新页面：`https://github.com/tanjiu90/f50pro-dualboot-kit/releases/latest`
> 2. 下载 **`F50Pro-Flasher-win64.zip`**（约 17 MB 绿色免安装包）。
> 3. **右键完整解压**到普通目录（如 `D:\F50Pro-Flasher`，**不要在压缩软件里直接双击**），双击运行 **`F50Pro-Flasher.exe`**（弹出管理员权限提示点「是」）。
> 4. 软件内置 **自动拉取 GitHub 最新版（支持国内镜像加速 + SHA-256 严格校验）**、**实时 USB 雷达（自动拦截非 MU3356 机型）**、**自动以 `--force --all` 预装展锐驱动**、**原厂密码提前验证** 与 **报错自动排查一键修复**，按界面 ① -> ② -> ③ 顺序点击即可完成刷机！
>
> *(如果你偏好命令行手动操作，或使用 macOS / Linux / 安卓 Termux，请继续阅读下方完整步骤。)*

---

## 零、开始前必读：安全红线与真实能力说明

在复制任何命令之前，请先花 1 分钟确认下面几条规则，可以帮你避开 99% 的变砖风险：

1. **严禁跨型号刷机**：
   - 本教程**仅支持中兴 F50 Pro（`MU3356`）**。
   - **绝对不能**用在普通 F50（`MU300`）、U30 Air、U30 Pro（`MU5358`）上，也**不能**把别人的备份文件直接刷进你的设备（每台机器必须现场备份自己原厂分区）。
2. **刷机过程中绝对不要强行拔线 / 断电**：
   - 本工具通过 `SPRD4:AutoD`（依赖设备现有引导区 `SPL + U-Boot`）读写闪存，**没有打包高通/展锐底层盲救砖所需的原厂签名 `FDL1/FDL2` 或 `.pac` 救砖包**。只要 `SPL + U-Boot` 完好就能正常读写；一旦强行断电破坏了引导区，工具自身无法盲救。
   - 工具默认启用多重保护锁（`FORBIDDEN_PARTITIONS`），绝不触碰射频/序列号/校准分区（`splloader`、`prodnv`、`calinv`、`ztecfg`、`persist`、`super`、`userdata` 等），而且**任何写入出错都会原地暂停、绝不盲目重启**。
3. **关于不同电脑系统与机型的实测边界（说实话不画饼）**：
   - **主控电脑最推荐 Windows 10 / 11（64 位）**：对插卡版 `B28` 已有完整双系统 + 5G 上网 + Wi-Fi + OpenClash + 5 秒按键双向切换实机验证；对 `B15`（内置双 eSIM）已完成无损备份、探测与调试修复，但由于测试机未开通付费 eSIM 流量，**`B15` 在 OpenWrt 下的 5G eSIM 蜂窝拨号上网需你用自己的已实名卡实测验证**。
   - **macOS / Linux / 安卓 Termux OTG**：命令行流程与自动测试已就绪，但**尚未在物理机上实际插线刷过 F50 Pro**；非 Root 安卓手机走 `--usb-fd` 属于**实验性分步手操**，小白强烈建议使用 **Windows 电脑**操作。
4. **必须保留一份原始全量备份**：
   - 备份文件夹大小约 **6.5 ~ 7 GB**，请确保电脑磁盘至少预留 **15 GB** 可用空间，备份成功后建议复制一份到另一个盘或网盘留底。

---

## 一、准备工作（小白照着打勾）

### 1. 准备硬件与信息
- [ ] **中兴 F50 Pro 设备 1 台**（能正常开机进原厂系统，记住**机身背面贴纸**或**管理网页 `http://192.168.0.1:8080` 的管理员登录密码**，后面脚本需要用它自动重启设备进刷机模式）。
- [ ] **一根靠谱的 USB 数据线**：必须是支持高速数据传输的线（原装线或手机原装数据线），不要用“只能充电的线”。
- [ ] **直连电脑主板 USB 口**：台式机尽量插机箱**背后主板** USB 口，笔记本直接插机身接口，尽量不要经过杂牌扩展坞或 USB 集线器。
- [ ] **一台能联网的 Windows 10 / 11 电脑**（下文以 Windows 为主流程；macOS / Linux / 安卓 Termux 见文末第七章）。

### 2. 在 Windows 上安装两个基础软件
如果你电脑上还没有 **Git** 和 **Python 3.11+**，请先安装：

1. **安装 Python 3.11 或 3.12（64 位）**：
   - 到官网 `https://www.python.org/downloads/` 下载安装包。
   - **⚠️ 关键一步**：打开安装向导第一页，**务必勾选最底部的 `Add python.exe to PATH`**，然后再点 `Install Now`！
2. **安装 Git for Windows**：
   - 到官网 `https://git-scm.com/download/win` 下载并一路默认下一步安装即可。
   - *（嫌装 Git 麻烦也可以跳过 Git，直接在 GitHub Releases 页面下载源码压缩包解压，下文也会说明。）*

---

## 二、先选好你要刷哪种模式（3 选 1）

本工具提供 3 套方案，刷机前想好选哪一套即可（小白最推荐 **方案 3**）：

| 方案名称 | 槽位 `_a`（安卓侧） | 槽位 `_b`（OpenWrt 侧） | 系统切换方式 | 适合人群 |
| :--- | :--- | :--- | :--- | :--- |
| **`1-android-ufi`** | 原厂安卓 + **Magisk Root** + **UFI-TOOLS** 高级管理后台 | 不改动 | 仅使用安卓系统 | 只想给安卓 Root、开 UFI-TOOLS 后台改串/锁频/看基站信息 |
| **`2-dual-stock-openwrt`** | **100% 原厂安卓只读不改** | 完整 **OpenWrt 25.12.5**（2 GiB 大容量、Wi-Fi 灯修复、可选 OpenClash） | OpenWrt 长按物理键 **5 秒**回原厂安卓；从原厂安卓切回 OpenWrt 需再用电脑 BROM 写入或重刷 | 想尝鲜 OpenWrt，同时希望原厂安卓槽位**一字节都不改** |
| **`3-dual-full`** ⭐**推荐** | 安卓 + **Magisk Root** + **UFI-TOOLS** + USB 防劫持隔离 | 完整 **OpenWrt 25.12.5**（2 GiB、Wi-Fi 灯修复、可选 OpenClash） | **任意系统下长按机身物理按键 5 秒，纯硬件双向热切换 (`OpenWrt <-> Android`)** | **绝大多数玩家首选**：既要 OpenWrt 科学分流/大空间插件，又要随时一键切回 Root 安卓 |

---

## 三、下载项目与一键安装依赖（Windows 完整步骤）

> 以下所有命令都在 **PowerShell** 中执行。建议全程不要把项目放到桌面或带中文/空格的路径下（例如放到 `D:\f50pro-kit`）。

### 第 1 步：打开 PowerShell 并下载代码

1. 按键盘 `Win + S`，搜索 **`PowerShell`**，右键选择 **“以管理员身份运行”**（因为第 3 步装 USB 驱动需要管理员权限）。
2. 依次复制执行以下命令（新建工作目录并下载官方 `v1.1.3` 稳定版代码）：

```powershell
mkdir D:\f50pro-kit -Force
cd D:\f50pro-kit
git clone --branch v1.1.3 --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
```

*(提示：如果之前没装 Git，也可以用浏览器打开 `https://github.com/tanjiu90/f50pro-dualboot-kit/releases/tag/v1.1.3` 下载 `f50pro-dualboot-kit-v1.1.3-src.tar.gz` 解压到 `D:\f50pro-kit\f50pro-dualboot-kit`，再 `cd` 进去。)*

### 第 2 步：运行一键引导脚本（创建 Python 环境 + 按需下载资源包）

Windows 默认禁止直接运行 `.ps1` 脚本，先执行第一条临时放行命令（只对当前窗口有效，安全无副作用），再运行引导脚本：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\bootstrap.ps1 -Interactive
```

运行后终端会出现交互菜单，**小白直接按下面这样选**（或者直接回车选默认值）：
1. **选择主机工具包**（`Select host tool bundle to download`）：直接回车选 `[1]`（自动识别为当前 `win64` 电脑，约 25.6 MB）。
2. **选择刷机方案所需固件包**（`Select deployment profile assets to download`）：
   - 选方案 3 就直接回车选 `[1]`；
   - 选方案 1 输入 `2` 回车；
   - 选方案 2 输入 `3` 回车。
3. **是否下载 OpenClash 干净离线包**（`Include optional offline OpenClash pack (~36 MiB)? [Y/n]`）：
   - 如果需要 OpenClash 分流功能，输入 `Y` 回车；不需要则输入 `n` 回车。

脚本会自动完成：
- 创建独立 `.venv` 虚拟环境并安装 `paramiko`、`pyserial`、`pytest`；
- 从 GitHub Releases 下载所选包并做 **SHA-256 完整性校验**；
- 在 `C:\Users\<你的用户名>\.android\` 下自动生成一套 ADB 公钥（`adbkey.pub`）。

> **离线兜底技巧**：如果国内直连 GitHub Release 下载慢，可以先用浏览器或下载器手动把 Releases 页面对应压缩包下好，直接放进 `D:\f50pro-kit\f50pro-dualboot-kit\bundle-cache\` 文件夹，再重新执行 `.\scripts\bootstrap.ps1 -Interactive`，它会自动走本地校验和解压，不再联网下载。

### 第 3 步：安装展锐 BROM / WinUSB 驱动（Windows 必做）

如果电脑之前没刷过展锐设备，必须先预装一次 `1782:4D00`（`Unisoc BROM`）和 `1782:4D03`（`Unisoc Boot Diag`）的 WinUSB 驱动，否则刷机工具在设备进入下载模式时找不到端口：

在同一个**管理员 PowerShell** 窗口执行：

```powershell
.\scripts\install_unisoc_drivers.bat
```

如果弹窗询问是否安装驱动，点 **安装 / 是**；看到 `Unisoc BROM` 和 `Unisoc Boot Diag` 两项都提示 **`Success`** 即安装完成（此时**不需要**先插设备，也不需要设备进入刷机模式）。

> **重要避坑（如果你遇到 `No matching device found`）**：
> - `qmk_driver_installer.exe` 不加 `--all` 参数时只会扫描**此刻已进入下载模式**的设备；而正常开机的 F50 Pro USB ID 是 `19D2:0246`（不是 `1782:4D00`），所以旧版 `v1.1.1` 漏掉 `--all` 时会提示 `No matching device found`。
> - `v1.1.2` 已将 `.\scripts\install_unisoc_drivers.bat` 与解压后的 `install_unisoc_drivers.bat` 全部修复为 `--force --all` 离线预装；如果你手里还是旧目录，可直接手动执行：
>   ```powershell
>   .\build\runtime-tools\host-tools-win64\qmk_driver_installer\qmk_driver_installer.exe --force --all .\build\runtime-tools\host-tools-win64\qmk_driver_installer\unisoc_drivers.txt
>   ```

### 第 4 步：执行电脑环境预检（不连接设备也能测）

```powershell
.\.venv\Scripts\python.exe scripts\kit.py preflight --strict --operation auto --profile 3-dual-full
```

*(如果你选的是方案 1 或方案 2，把上面 `3-dual-full` 换成 `1-android-ufi` 或 `2-dual-stock-openwrt`。)*

看到输出的 JSON 里包含 **`"ready": true`** 且没有报错，说明电脑端环境已经 100% 就绪！

---

## 四、核心操作：备份原厂系统 -> 干跑预览 -> 一键刷入

下面提供两种操作方式。**强烈推荐小白先走「方法 A：先备份、看预览、再刷机」**，虽然多输两条命令，但能先保住完整原厂备份并看到自己设备的型号检测结果。

> **插线准备**：现在用 USB 数据线把 **F50 Pro** 连接到电脑。等大概 20 秒，确保设备已开机，或者能在浏览器打开原厂后台 `http://192.168.0.1:8080`。

### 方法 A：稳妥三步走（强烈推荐零基础小白）

#### 步骤 A1：全量只读备份原厂闪存（约 2～5 分钟）
把下面命令里的 `<你的WebUI密码>` 替换成你登录 `192.168.0.1:8080` 的密码（保留英文双引号）：

```powershell
.\.venv\Scripts\python.exe scripts\kit.py backup `
  --output-dir build\my-f50pro\backup `
  --authorize-device-reboot `
  --webui-password "<你的WebUI密码>"
```

- **期间发生了什么**：脚本会调用原厂 WebUI 接口自动重启设备进入 `SPRD4:AutoD` 模式，并读取全部原厂分区到 `build\my-f50pro\backup\`，然后自动重启回原系统。
- **如果没有原厂 WebUI 密码怎么办？** 可以去掉 `--webui-password "..."` 参数运行上面命令。当屏幕出现 `Waiting for boot_diag` 提示时，按照对应方式手动触发设备重启/短接进入下载模式即可（前提设备还能重启进 `boot_diag`）。
- **成功标志**：输出 JSON 显示 **`"checks_passed": true`**。
- **⚠️ 重要动作**：备份完成后，把 `D:\f50pro-kit\f50pro-dualboot-kit\build\my-f50pro\backup` 整个文件夹**复制一份存到 D 盘其他位置或网盘**作为保底备份！

#### 步骤 A2：100% 离线干跑预览（绝对安全，不写设备、不重启）
执行离线计划生成（以下以**方案 3 + OpenClash**为例）：

```powershell
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\my-f50pro `
  --openclash
```

> **注意**：不加 `--execute` 参数时，脚本处于 **纯离线演练模式（`offline_plan_dry_run`）**，不会联网、不会重启、不会往设备写任何 1 个字节。

检查输出里的关键信息：
- `"status": "DRY_RUN_READY"`
- `"inspect"` 中的 `"trustos_a"` 补丁偏移与 `"vendor_boot_a"` DTB 摘要已自动识别（注：离线备份阶段 `"board_id"` 为 `null`，会在刷入 OpenWrt 连上 SSH 后实时读取为 `"6"` 或 `"1"`）
- `"device_mutated": false`
- 也可以打开 `build\my-f50pro\build\flash_plan.json` 看一眼写入清单，确认被禁止分区（`FORBIDDEN_PARTITIONS`）写入数为 0。

#### 步骤 A3：正式开始刷机与自动配网（加 `--execute`）
确认预览没问题后，执行正式刷入命令。**注意这里强烈建议加上 `--wifi-password` 和 `--generate-password`**，自己定好 OpenWrt 的 Wi-Fi 密码并随机生成安全的管理员 root 密码：

```powershell
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\my-f50pro `
  --reuse-backup `
  --webui-password "<你的WebUI密码>" `
  --wifi-ssid F50Pro-OpenWrt `
  --wifi-password "<你要设置的WiFi密码_至少8位>" `
  --generate-password `
  --openclash `
  --execute
```

*(如果不需要 OpenClash，去掉 `--openclash`；如果选方案 1 `1-android-ufi`，不需要 `--wifi-ssid` / `--wifi-password` / `--openclash` / `--generate-password`；如果选方案 2 `2-dual-stock-openwrt`，写法与方案 3 相同只是 `--profile 2-dual-stock-openwrt`。)*

---

### 方法 B：单次会话零插拔极速一键（适合想一条命令跑完）

如果你已经确认好备份空间和参数，不想分步敲命令，可以直接省略 `--reuse-backup` 并直接带上 `--execute`：

```powershell
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\my-f50pro `
  --webui-password "<你的WebUI密码>" `
  --wifi-ssid F50Pro-OpenWrt `
  --wifi-password "<你要设置的WiFi密码_至少8位>" `
  --generate-password `
  --openclash `
  --execute
```

`v1.1.1` 支持**单次 `SPRD4` 会话不断线**：设备只需进入一次刷机模式，会在同一个 USB 会话里连续完成「全量备份 -> 校验 -> 本机派生镜像 -> 分区写入与读回 SHA-256 核对 -> 切槽重启」，中间无需手动插拔 USB。

---

## 五、刷机过程会发生什么？（请耐心等待，不要拔线！）

执行 `--execute` 后大约需要 **5～10 分钟**，期间电脑和设备会出现以下**完全正常**的现象：

1. **自动进刷机模式并读写分区**：设备重启进入 `SPRD4:AutoD`，所有写入的分区（`boot_b`、`vendor_boot_b`、`trustos_b`、`fulldumpdb` 等）在写完后**都会立刻整块读回来做 SHA-256 比对**，完全一致后才切换活动槽位。
2. **USB 网卡自动隔离（你电脑不会断网！）**：
   - 刷完 OpenWrt 首次开机时，F50 Pro 会给电脑虚拟出一张 USB 网卡。`host_network.py` 会自动把这张 USB 网卡设为静态管理 IP **`192.168.77.12`**，并清空它的默认网关和 DNS，**防止抢走你电脑原本的 Wi-Fi/宽带网络**。
3. **Windows 10 自动串口恢复（如遇到属于正常）**：
   - 部分 Windows 10 电脑上 OpenWrt 默认的 `CDC-NCM` 网卡驱动可能装不上（设备管理器打黄色感叹号）。工具会在等待 5 秒后**自动通过设备的串口 `MI_02` 登录进去把 USB 模式切换为 Windows 原生免驱的 `RNDIS`**，再继续往下配网，全程全自动无需手动干预。
4. **OpenWrt 自动配网**：
   - 自动将根文件系统无损在线扩容至完整 **`2 GiB`**；
   - 自动修复插卡版 `board_id=6` 选卡脚本、修复 Wi-Fi 白色指示灯、注入 **长按机身按键 5 秒切换系统** 脚本；
   - 如果加了 `--openclash`，自动离线安装 OpenClash + Mihomo 内核 + 地理库 + 空模板；
   - 自动保存随机生成的 root 密码到 `build\my-f50pro\build\openwrt-credentials.json`。
5. **安卓槽位自动配网（仅方案 1 和方案 3）**：
   - 在 OpenWrt 下安全写入并核对已集成 **Magisk Canary 28103** 的 `init_boot_a` 与去 AVB 的 `trustos_a`；
   - 重启进安卓 `_a` 完成 Magisk 与 **UFI-TOOLS**（`:2333` 与网页终端 `:1146`）部署并做一次冷重启验证；
   - 验证通过后（方案 3）自动切回 OpenWrt `_b`，输出最终端到端验收报告 `build\my-f50pro\final_verify_report.json`。

当你看到最终输出 **`"overall_status": "PASS"`** 且命令正常退出（返回码 `0`），就大功告成了！

---

## 六、刷好后怎么用？（小白日常操作指南）

### 1. 登录 OpenWrt 路由器管理后台
1. **查看你的密码**：用记事本打开：
   `D:\f50pro-kit\f50pro-dualboot-kit\build\my-f50pro\build\openwrt-credentials.json`

   里面的 `"password"` 就是你的 OpenWrt 管理员（`root`）密码和 SSH 密码。
   *(提示：如果你刷机时既没加 `--generate-password` 也没加 `--root-password`，默认可能为空密码或 `root`，建议进后台后立刻改密码！)*
2. **打开管理网页**：
   - USB 插在电脑上，或手机/电脑连上设备 Wi-Fi **`F50Pro-OpenWrt`**（若刷机时未指定 `--wifi-password`，OpenWrt 底包初始默认 Wi-Fi 密码为 **`openwrt1234`**，请尽快进后台修改！）。
   - 浏览器打开 **`http://192.168.77.1`**，用户名 `root`，密码填上面查到的密码，即可进入中文 LuCI 管理页面。

### 2. 配置 OpenClash（如果刷机时带了 `--openclash`）
为了安全与隐私，内置模板 `template.yaml` **不包含任何代理节点和订阅**（仅空模板 `proxies: []`）：
1. 打开 `http://192.168.77.1` -> 左侧菜单 **服务 -> OpenClash -> 配置订阅**。
2. 点击添加，填入你自己的 Clash Meta / Mihomo 订阅链接，保存并更新配置。
3. 切换配置文件后启动 OpenClash，即可通过 **`http://192.168.77.1:9090/ui/metacubexd`** 进入代理控制面板。

### 2.5 无卡 / 有卡 Wi-Fi 中继（手机与电脑均可后台一键切换）
刷入 OpenWrt 后已自动内置 **「Wi-Fi 中继」** 模块（含 `aicwf_sdio` 并发 AP+STA 修复与 **25 秒防失联自动回退纯热点守护**），**不插 SIM 卡也能作为便携中继软路由使用**：
1. 手机或电脑连接 `F50Pro-OpenWrt`（或 USB 插电脑），打开 `http://192.168.77.1` -> **网络 -> Wi-Fi 中继**。
2. 点击 **「扫描周围 Wi-Fi」**（支持 2.4 GHz 与 5 GHz 合并扫描），点选要中继的上级 Wi-Fi（支持 WPA2 与 WPA2/WPA3 混合），输入密码点击 **「保存并连接中继」**。
3. 支持即时切换 **上网出口优先级**（无需重启 Wi-Fi）：
   - **Wi-Fi 中继优先**：插卡时也先走上级 Wi-Fi，断网自动切回流量卡；
   - **流量卡优先**：无卡或蜂窝断开时自动切走 Wi-Fi 中继；
   - **仅 Wi-Fi 中继**：彻底停用蜂窝口，零流量消耗。
4. **防失联保护**：如果不小心输错密码或带着设备离开上级 Wi-Fi 覆盖区，约 **25 秒**后设备会自动回退并拉起 `F50Pro-OpenWrt` 纯热点，手机重连本机热点打开 `http://192.168.77.1` 即可重新扫描切换，无需插电脑救场。

### 3. 如何切卡（插卡 vs eSIM）与红灯排查
- **插卡版（`B28` / `board_id=6`）**：在 OpenWrt LuCI 首页即可看到物理卡（Nano-SIM）与内置 eSIM 的通道切换选项。
- **内置双 eSIM 版（`B15` / `board_id=1`）**：出厂一般自带移动 + 电信两张内置 eSIM，若其中一张未实名/未开通流量，信号灯可能亮**红灯**，在 LuCI 首页切换到已激活的那张 eSIM 槽位即可。

### 4. 如何切换系统（OpenWrt <-> 安卓）
- **方案 3（`3-dual-full`）双向硬件热切换**：
  - 无论当前在 OpenWrt 还是安卓下运行，**按住 F50 Pro 机身上的实体按键持续 5 秒以上**，看到指示灯闪烁蓝灯/绿灯确认后松手，设备会自动切换引导槽位并重启进入另一个系统！
  - 也可以在 OpenWrt SSH 里执行 `/opt/mu300/bin/mu300-next-boot android && reboot` 切到安卓。
- **方案 2（`2-dual-stock-openwrt`）单向回退**：
  - 在 OpenWrt 下长按按键 **5 秒** 可回原厂安卓；但因为原厂安卓未做 Root 改写，从原厂安卓无法直接按键切回 OpenWrt（需要用电脑执行 `wof` 或重刷）。

### 5. 如何打开安卓侧的 UFI-TOOLS 与网页终端
- **在方案 3 下**：为了防止安卓侧插回 Windows 时偷跑手机流量或劫持电脑断网，安卓侧默认设置为了 **`charging,adb`（仅充电 + ADB，不向电脑暴露 USB 网卡）**。
  - 所以切到安卓后，用手机或电脑**连接 F50 Pro 发出的安卓 Wi-Fi 热点**，然后浏览器访问：
    - **UFI-TOOLS 后台**：`http://192.168.0.1:2333`
    - **网页终端 (ttyd)**：`http://192.168.0.1:1146`（默认使用 UFI-TOOLS 应用内设置的登录口令；若应用尚未设置口令，请查看本机生成的随机初始口令文件 `build\<session>\build\android-ttyd-credentials.json`，已彻底移除 APK 硬编码后备口令）
  - 电脑端也可以在 USB 直连时通过 `adb shell` 调试（已自动内置免弹窗 RSA 公钥）。
- **在方案 1 下**：默认保持 `rndis,serial_smd,diag,adb`，插 USB 即可直接访问 `http://192.168.0.1:2333` 和 `:1146`（初始网页终端随机口令同样保存在 `android-ttyd-credentials.json`）。

### 6. 电脑端上网与管理口模式切换（防断网隔离）
- 平时插在电脑上只想当管理口、**不抢电脑原本 Wi-Fi/宽带网络**，工具默认就是 `management` 隔离模式（电脑保持原网络，通过 `192.168.77.1` 管理路由器）。
- 如果需要手动重新隔离管理口或审计路由是否泄露，可运行：
  ```powershell
  .\.venv\Scripts\python.exe scripts\host_network.py isolate
  .\.venv\Scripts\python.exe scripts\host_network.py audit
  ```
- 如果确实希望电脑**通过 USB 借用 F50 Pro 的 5G 流量上网**，可切换为 `internet-exit` 出口模式（用完随时再运行 `isolate` 改回隔离模式）：
  ```powershell
  .\.venv\Scripts\python.exe scripts\host_network.py isolate --mode internet-exit
  ```

---

## 七、其他电脑系统简要指引（macOS / Linux / 安卓 Termux）

如果你使用的不是 Windows 电脑：

1. **Linux（`x86_64` / `aarch64`）**：
   - 安装引导：`bash scripts/bootstrap.sh --interactive`
   - 安装免 root USB 规则（推荐，避免整套脚本以 root 运行）：
     ```bash
     sudo cp assets/udev/99-unisoc-f50pro.rules /etc/udev/rules.d/
     sudo udevadm control --reload-rules && sudo udevadm trigger
     ```
   - `aarch64` 架构需额外装系统 `adb`：`sudo apt-get install -y android-tools-adb`
   - 后续把命令里的 `.\.venv\Scripts\python.exe` 换成 `.venv/bin/python` 即可。

2. **macOS（M 系列 Apple Silicon / Intel 通用）**：
   - 安装引导：`bash scripts/bootstrap.sh --platform macos --interactive`
   - 由于 macOS 底层 `libusb` 独占 USB 刷机口必须提权，在执行 `backup`、`flash`、`auto --execute` 时需加 `--spd-mode sudo`（会提示输入 Mac 开机密码），例：
     ```bash
     .venv/bin/python scripts/kit.py auto --profile 3-dual-full --work-dir build/my-f50pro --spd-mode sudo --webui-password "<密码>" --generate-password --execute
     ```

3. **安卓手机 / 平板 OTG（Termux）**：
   - 请务必从 **F-Droid** 安装 `Termux` 和 `Termux:API`（勿用 Google Play 旧版）。
   - **已 Root 手机**：加 `--spd-mode su`，支持完整 `--kickto 2` 自动抓端口流程。
   - **未 Root 手机**：`--spd-mode termux-usb` 为**实验性工具**，因系统单次 USB FD 授权在设备重启/重置后即失效，无法自动跑完一键闭环，不推荐零基础小白使用。

---

## 八、常见问题与故障急救（Troubleshooting）

### Q1：刷机途中突然报错中断了怎么办？会变砖吗？
- **先看屏幕和报错文件，不要慌张反复断电！**
- 工具在写入/读回比对失败时，会**主动停止且不发送 `reset` 重启命令、不切换槽位**，并生成：
  - `build\my-f50pro\build\flash-run\flash_state.json`
  - `build\my-f50pro\build\flash-run\flash_failure_report.json`
- 绝大多数情况下原本的系统分区（`_a` 槽）丝毫未损！只要确认是连接线松动或读回校验失败，排除线材/USB 口后重新执行带 `--reuse-backup` 的命令或写回原槽引导块即可。

### Q2：装驱动报 `No matching device found`，或 F50 Pro 插电脑完全识别不到 / 卡在 `Waiting for boot_diag`？
1. **运行驱动脚本提示 `No matching device found`**：
   - 这是缺少 `--all` 参数导致的（正常开机的 F50 Pro 是 `19D2:0246`，不会在安装驱动时显示 `1782:4D00`）。
   - 请在**管理员 PowerShell** 中运行 `.\scripts\install_unisoc_drivers.bat`（或手动加 `--force --all` 参数执行 `qmk_driver_installer.exe --force --all ...\unisoc_drivers.txt`），直到两项都显示 `Success`。
2. **正常开机插电脑就识别不到（打不开 `http://192.168.0.1:8080`，设备管理器没反应）**：
   - **优先换数据线和 USB 口**：很多纯充电线或双头 Type-C 线不支持高速数据；换一根确认能给手机传数据的 **USB-A 转 Type-C 线**，直插台式机**主板后置 USB 口**（不要走扩展坞/前置面板）。
   - **检查设备管理器 RNDIS 驱动**：正常开机插上电脑应出现 `VID_19D2&PID_0246`（Remote NDIS 网卡）。若出现带黄色感叹号的未知设备/RNDIS，右键 **更新驱动程序 -> 浏览我的电脑 -> 让我从计算机上的可用驱动程序列表中选取 -> 网络适配器 -> Microsoft -> 基于远程 NDIS 的 Internet 共享设备**。
3. **驱动已装仍卡在 `Waiting for boot_diag`**：
   - 确认你的 `--webui-password` 输入正确（如果输入错误脚本会立刻报 `WebUIAuthError` 退出）；
   - 如果电脑以前装过老版展锐串口驱动（`SPRD U2S Diag` 抢占了 `1782:4D00`），可用 **Zadig**（`Options -> List All Devices`）在刷机窗口将 `1782:4D00` 强行替换为 **WinUSB**；
   - 若你不知道原厂 WebUI 密码（也进不去后台），可在出现 `Waiting for boot_diag` 时手动按厂商进线刷模式方式重新插拔上电。

### Q3：提示 `Target unit identity mismatch`（设备指纹不匹配）？
- 说明你拿**A 机器的 `backup`** 去刷 **B 机器** 了！这是安全锁主动救了你一命——请为当前插着的设备新建一个 `--work-dir`（例如 `build\device-2`）重新备份并生成计划。

### Q4：怎么还原回纯原厂状态？
- **情况一：卡在 OpenWrt `_b`，只想切回原厂安卓 `_a`**
  - 若能通过 USB/Wi-Fi 连上 OpenWrt：直接长按按键 5 秒，或在 SSH 里执行 `/opt/mu300/bin/mu300-next-boot android && reboot`。
  - 若进不去系统但能进 `SPRD4` 下载模式，把构建目录生成的 `misc_rollback_a.bin` 写回 `misc` 偏移 `2048` 处即可切回 `_a`：
    ```powershell
    .\build\runtime-tools\host-tools-win64\spd_dump_251\spd_dump.exe --wait 120 --kickto 2 `
      wof misc 2048 build\my-f50pro\build\stage3\misc_rollback_a.bin reset
    ```
- **情况二：彻底还原已修改过的系统分区回出厂状态**
  - 使用你最初备份的 `build\my-f50pro\backup\` 目录，只写回被修改过的引导区与 `misc`（**切勿覆盖 `prodnv`/`calinv`/`ztecfg`/`persist`/NV 分区**；若当初只刷了方案 1 `1-android-ufi`，只需写回 `trustos_a` 与 `init_boot_a`；若当初刷了方案 2 `2-dual-stock-openwrt`，`trustos_a` 与 `init_boot_a` 本就未改动，无需写回这两项）：
    ```powershell
    .\build\runtime-tools\host-tools-win64\spd_dump_251\spd_dump.exe --wait 120 --kickto 2 `
      w trustos_a build\my-f50pro\backup\trustos_a `
      w init_boot_a build\my-f50pro\backup\init_boot_a `
      w trustos_b build\my-f50pro\backup\trustos_b `
      w boot_b build\my-f50pro\backup\boot_b `
      w vendor_boot_b build\my-f50pro\backup\vendor_boot_b `
      w_force init_boot_b build\my-f50pro\backup\init_boot_b `
      wof misc 2048 build\my-f50pro\build\stage3\misc_rollback_a.bin `
      reset
    ```

### Q5：运行 `kit.py probe` 进行一键只读体检
任何时候想检查设备当前双系统、按键配置、OpenClash 和宿主机网络路由是否健康，都可以运行只读巡检（不重启、不改设备）：

```powershell
.\.venv\Scripts\python.exe scripts\kit.py probe `
  --profile 3-dual-full `
  --credentials-file build\my-f50pro\build\openwrt-credentials.json `
  --openclash
```
