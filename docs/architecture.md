# 技术架构说明 (`MU3356` / `UMS9632` A/B 双槽与纯 Python 离线构建原理)

## 1. 存储与分区双槽架构

ZTE F50 Pro (`MU3356`) 采用 Unisoc `UMS9632` 芯片与标准 Android 15 动态分区（A/B 双槽布局）：
- **不可破坏共享基石分区（禁止脚本写入）**：`splloader`、`prodnv`、`calinv`、`ztecfg`、`ztepersist`、`persist`、`miscdata`、`super`、`userdata` 以及调制解调器射频 NV / 校准分区（详见 `common.py` `FORBIDDEN_PARTITIONS`）。
- **槽位 `_a`**：存放 Android 15 内核与启动镜像（`trustos_a`, `sml_a`, `boot_a`, `vendor_boot_a`, `init_boot_a`）。
- **槽位 `_b` + `fulldumpdb`**：
  - 将原厂 12 组 BSP 分区（`uboot`, `sml`, `teecfg`, `dtbo`, `vbmeta*`, `logo*`, `fbootlogo*`）同步到 `_b`，保证与目标设备硬件指纹 100% 一致；
  - `trustos_b` 使用本机衍生无 AVB 拦截镜像；
  - `boot_b` 封装 OpenWrt 通用 Linux 6.12.94 内核镜像与统一 initramfs（Boot v4 + 保留 AVB 页脚）；
  - `vendor_boot_b` 严密校验并复用本机 `vendor_boot_a` 的 DTB SHA-256，附加 `mu3356` SIM mux 与无电池外部供电参数到 `bootconfig`；
  - `init_boot_b` 使用合规最小空 ramdisk 重新打包并保留原尺寸及 AVB 结构（以 `w_force` 配合写入后 GPT 完整性核验写入）；
  - `fulldumpdb`（`2 GiB` / `2,147,483,648` B）：承载 OpenWrt ext4 根文件系统。

> **关于 `fulldumpdb` 与系统内存的常见误解**：`2 GiB` 在此方案中是 `fulldumpdb` eMMC 用户区给 OpenWrt 系统占用的存储空间；设备 RAM 本身物理容量由硬件决定（DTB `/memory*/reg` 报告），`f50pro-capacity.uc` 会在 LuCI 首页清晰区分**物理内存 vs 内核可管理内存**以及**系统根存储 vs 整机闪存总容量**。

## 2. 本机 `trustos` 无 AVB 镜像衍生原理（Zero Foreign Binary）

F50 Pro 出厂 `sml_a` 与 `trustos_a` 均包裹 Unisoc `DHTB` 头（`0x200` 字节）与 `SIMGHDR\x00` 签名尾：
- 工具包**绝不分发也不刷入任何来自他机的 `trustos` 文件**；
- `inspect_backup.py` 使用 64 字节唯一上下文指纹 (`TRUSTOS_AVB_SIG_ORIG`) 在目标设备自身 `trustos_a` 代码载荷中准确定位 4 字节 TEE AVB 判决指令 (`e0031a2a` -> `00008052`)：
  - `board_id=1`（内置双 eSIM 版）典型偏移：`0x981ec`
  - `board_id=6`（插卡版）典型偏移：`0x9856c`
- `build_images.py` 将修改后的本机载荷套入本机 `sml_a` 的合法 `DHTB` + `SIMGHDR` 外壳结构，按增量同步更新 `0x30` payload size 及 `SIMGHDR` 内 `0x18`/`0x28` 偏移值，最后补齐至目标分区精确字节数。

## 3. 纯 Python 无 WSL `init_boot_a` 打包流水线

传统做法常依赖 Windows 上的 WSL + `magiskboot` 二进制。本工具链使用标准库完全在原生 Windows Python 3.11+ 下重建 Android Boot v4 `init_boot_a`：
1. 解析出厂 `init_boot_a` 的 `ANDROID!` v4 头部与尾部 `AVBf`/`AVB0` 结构；
2. 解码原厂 `LZ4` legacy ramdisk 并解析 `070701` (`newc`) CPIO 归档列表；
3. 从正版 `Magisk-canary-28103.apk` 内部精确提取 `libmagiskinit.so` 替换 `init`，并打包 `overlay.d/`、`magisk.xz`、`init-ld.xz`、`stub.xz`（全部以 `lzma.FORMAT_XZ + lzma.CHECK_CRC32` 压缩）；
4. 写入规范的 `.backup/.magisk`、`SHA1` 原包摘要、`.backup/.rmlist`（以 NUL 分隔的覆盖物列表）及 `.backup/init.xz`；
5. 重建 deterministic `newc` CPIO 与合法对齐 `LZ4` legacy 区块，保持原始 `ANDROID!` v4 页结构并在分区末尾原位回填完整 `AVB0` vbmeta 与精确更新 `AVBf` 64 字节页脚。

## 4. `misc+2048` (`BCAB`) 原子双槽控制

Android A/B `bootloader_control` 位于 `misc` 分区偏移 `2048` 字节（共 `32` 字节，含小端序尾 `CRC32` 校验）：
- 刷入 `_b` 后，最后一步仅通过 `spd_dump wof misc 2048 ...` 写入 32 字节试跑块（`priority=15`, `tries_remaining=3`, `active=1`），并在写入后立即执行整分区读回字节级比对。若 `_b` 前 3 次均未能成功进入系统并完成确认，`uboot` 自动回落到 `_a`。
- 配置 3 在 Android `_a` 初始化前额外挂载 480 秒超时退回守护：如果在首次初始化尚未生成 `/data/adb/f50pro-android-test-complete` 且未持有测试锁定文件期间卡死，计时到期自动恢复此前验证过可启动的 `known-good-b-bcab.bin` 并重启回 OpenWrt `_b`。
