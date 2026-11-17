# 故障排查、BROM 恢复与宿主网络安全说明

## 1. Windows 驱动准备：Unisoc `SPRD4:AutoD` (`1782:4D00`)

本设备使用 Unisoc `SPRD4:AutoD` 免外部 FDL 直连下载模式，无需旧版第三方 FDL1/FDL2。

- 当执行 `kit.py backup` 或 `kit.py flash` 时，工具可传入 `--webui-password` 自动通过本地 ZTE WebUI 接口向设备发送安全重启命令；当屏幕上出现 `Waiting for boot_diag` 时，带 `--kickto 2` 参数的 `spd_dump.exe` 会自动拦截重启链路上的 BROM 握手口并进入高速只读/写入通道。
- **如果全新电脑首次连接出现未知 USB 设备（`VID_1782&PID_4D00` 缺少驱动）**：
  1. 以管理员运行随工具链释放的 `build\runtime-tools\host-tools-win64\qmk_driver_installer\qmk_driver_installer.exe`（或 Zadig），将设备接口绑定为 **`WinUSB`**；
  2. 随后重新执行 `kit.py backup` 或 `kit.py flash` 即可识别并保持连接。

---

## 2. Windows 宿主网卡防劫持 (`host_network.py`)

每次插上刷好 OpenWrt 的 F50 Pro（`VID_1D6B&PID_0104` RNDIS + ACM）或带 `rndis` 的 Android 时，Windows 默认可能尝试 DHCP 获取并将设备当成主互联网网关，导致本机电脑原本的宽带/Wi-Fi 网络断网。

本工具包内置 [host_network.py](../scripts/host_network.py)，提供自动三层防御（在 `provision-openwrt` 时默认自动生效，也可手动随时单独调用）：
1. **清理负向缓存**：清除 `HKLM:\SYSTEM\CurrentControlSet\Control\UsbFlags\1D6B01040612` 注册表项；
2. **原生驱动自绑定**：调用 Windows `setupapi`/`newdev` API 为现存 RNDIS 设备绑定微软自带 `C:\Windows\INF\netrndis.inf` RNDIS6 驱动，无需人工手选 INF；
3. **纯内网隔离**：将 RNDIS 网卡固定配置为 `192.168.77.12 / 255.255.255.0`，清空 `DefaultGateway`、DNS 服务器、关闭 IPv6 绑定，将接口跃点数设为 `5000`，并执行 `audit_default_routes()` 强制核验操作系统 `0.0.0.0/0` 默认路由表中绝不包含 `192.168.77.*` 或 `192.168.0.*`。

手动运行网络修复与审计：

```powershell
.\.venv\Scripts\python.exe scripts\host_network.py --install --isolate --audit
```

---

## 3. 紧急恢复方案（Rollback to Factory）

因第一步备份保存了完整原始镜像（含原厂 `boot_a`, `init_boot_a`, `trustos_a`, `misc` 与全部 BSP 分区），任意时刻都可无损恢复：

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
