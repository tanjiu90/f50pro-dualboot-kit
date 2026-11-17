# OpenClash 干净离线包与模板使用指南

## 1. 离线包组成（零个人隐私与代理节点）

Release `v1.0.0` 中的可选扩展包 `f50pro-openclash-offline-25.12.5-arm64.tar.gz` 仅包含公开组件，不包含任何个人订阅链接、账号令牌、落地节点或自定义私有配置：
- **OpenWrt `25.12.5` AArch64 `.apk` 依赖与主程序包**：共 `27` 个签名安装包（`luci-app-openclash`、`dnsmasq-full`、`ruby`、`lua`、网络过滤依赖库等）；
- **Meta 内核**：`mihomo-linux-arm64-v1.19.34.gz`（自动解压安装至 `/etc/openclash/core/clash_meta`）；
- **地理库**：`GeoSite.dat` 与 `Country.mmdb`（安装至 `/etc/openclash/`）；
- **纯净中立规则模板**：[assets/openwrt-patch/openclash-clean/template.yaml](../assets/openwrt-patch/openclash-clean/template.yaml) 与统一初始化脚本 [openclash-uci-apply.sh](../assets/openwrt-patch/openclash-clean/openclash-uci-apply.sh)。

---

## 2. 模板默认行为说明

`provision_openwrt.py --openclash` 启用后会自动下发以下标准安全配置：
- `core_type = Meta` / `core_version = linux-arm64`
- `operation_mode = fake-ip` / `en_mode = fake-ip`
- 管理面板端口 `9090`，默认面板 `metacubexd`
- 模板默认配置为空代理池（`proxies: []`、默认规则兜底 `DIRECT`），确保脱敏干净且首次开机服务与 `:9090` 面板可完整拉起。

---

## 3. 在设备交付后配置您的私人订阅

设备刷机完成并交付后，按需二选一方式接入您自己的订阅源：

1. **Web 面板配置（推荐）**：
   - 浏览器打开 OpenWrt LuCI (`http://192.168.77.1`) -> **服务 -> OpenClash -> 配置订阅**；
   - 添加您自己的 Clash Meta / Mihomo 订阅 URL 并应用启动（Meta 面板地址：`http://192.168.77.1:9090/ui/metacubexd`）。
2. **直接替换 `/etc/openclash/config/` 下的配置文件**：
   - 通过 SSH 登录后将您的订阅/配置文件上传至 `/etc/openclash/config/` 并切换 `uci set openclash.config.config_path=... && uci commit openclash`；
   - 执行 `/etc/init.d/openclash restart` 即可。

> 请注意：**切勿将任何包含个人订阅 URL 或节点信息的配置文件重新提交回本公开 Git 仓库。**
