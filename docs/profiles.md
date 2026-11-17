# 刷机配置方案详述 (`1-android-ufi` / `2-dual-stock-openwrt` / `3-dual-full`)

本工具包在完全相同的本地纯 Python 离线构建链下提供三种可自由选择的部署配置。所有配置均共用第一步的只读全量 BROM 备份与本机 `trustos` 衍生机制。

---

## 配置对比矩阵

| 维度 | `1-android-ufi` (配置 1) | `2-dual-stock-openwrt` (配置 2) | `3-dual-full` (配置 3 · 推荐) |
| :--- | :--- | :--- | :--- |
| **槽位 `_a` (Android 15)** | Rooted (`Magisk 28103`) + **UFI-TOOLS** + `ttyd :1146` + RSA ADB 授权 | **100% 原厂只读不改**（官方 OTA / 官方系统状态完整保留） | Rooted (`Magisk 28103`) + **UFI-TOOLS** + `ttyd :1146` + `charging,adb` 隔离 |
| **槽位 `_b` (OpenWrt 25.12.5)** | 未写入 / 保持出厂状态 | 完整写入 (`Linux 6.12.94`, `2 GiB`, 容量界面, LED 修复, `rndis+acm`, 可选 OpenClash) | 完整写入 (`Linux 6.12.94`, `2 GiB`, 容量界面, LED 修复, `rndis+acm`, 可选 OpenClash) |
| **系统切换方式** | 仅 Android | `OpenWrt -> Android`: 长按机身按键 5 秒或 LuCI/命令行 `mu300-next-boot android`；进入原厂 Android 后可通过 BROM `wof` 或重刷激活 `_b` | **免拆机纯物理双向切换**: 任意系统下长按按键 **5 秒** 无缝往返 `OpenWrt <-> Android` |
| **Android USB 模式默认** | `rndis,serial_smd,diag,adb`（可经 `--usb-mode` 调整） | 原厂默认 | `charging,adb`（隔离 Android USB 网卡，杜绝插回 Windows 时意外通过蜂窝走流量） |
| **安全性与容错** | 纯 BROM 读取校验 | 槽位 `_a` 物理零触碰，`_b` 首次 3 次试跑失败自动回退原厂 Android | 先用 BROM 写入并跑通 OpenWrt `_b`，再在 OpenWrt 中校验写入 `_a`；`_a` 首次内置 480 秒未完成配对自动回滚至 `_b` 兜底机制 |

---

## 各配置快速启动命令

### 配置 1：`1-android-ufi`（纯安卓高级后台）

```powershell
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 1-android-ufi `
  --work-dir build\device-p1 `
  --webui-password "<WEBUI_PASSWORD>" `
  --execute
```

交付结果：原机 Android 获 Magisk 28103（10+1 运行库入驻 `/data/adb/magisk`）、RSA 公钥免弹窗 ADB、随开机自动拉起的 UFI-TOOLS 后台（`http://192.168.0.1:2333`）与 Web 终端（`:1146`）。

---

### 配置 2：`2-dual-stock-openwrt`（原厂安卓 + OpenWrt）

```powershell
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 2-dual-stock-openwrt `
  --work-dir build\device-p2 `
  --webui-password "<WEBUI_PASSWORD>" `
  --generate-password `
  --openclash `
  --execute
```

交付结果：
- 原厂槽位 `_a` 未改写任何字节（连 `trustos_a` / `init_boot_a` 都完全原样保留）；
- 槽位 `_b` 写入 `25.12.5`，支持 `2 GiB` 根目录、LuCI 容量展示、Wi-Fi 灯修复、5s 长按回退原厂 Android。

---

### 配置 3：`3-dual-full`（安卓高级后台 + OpenWrt 完全体双系统）

```powershell
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\device-p3 `
  --wifi-ssid F50Pro-OpenWrt `
  --webui-password "<WEBUI_PASSWORD>" `
  --generate-password `
  --openclash `
  --execute
```

交付结果：
1. 两个槽位分别承担不同角色：OpenWrt 负责专业旁路/规则分流/实体键调度/2 GiB 插件生态，Android Root 保留 UFI-TOOLS 生态与原生蜂窝工具箱；
2. 480 秒首启自检完成后固化，日常通过物理长按 5 秒在两大完整系统间热切；
3. 宿主 Windows `host_network.py` 自动解除设备自带 RNDIS 默认路由劫持，保持台式机/笔记本本机互联网出口稳定。
