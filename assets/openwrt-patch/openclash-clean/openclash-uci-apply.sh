#!/bin/sh
set -eu
mkdir -p /etc/crontabs /etc/openclash/config /etc/openclash/core
[ -f /etc/crontabs/root ] || touch /etc/crontabs/root

# Preserve any existing template or user-configured subscription on re-run.
if [ ! -f /etc/openclash/config/template.yaml ]; then
  cp -f /tmp/openclash-template.yaml /etc/openclash/config/template.yaml
fi

CUR_CFG="$(uci -q get openclash.config.config_path 2>/dev/null || true)"

uci set openclash.config.core_type='Meta'
uci set openclash.config.core_version='linux-arm64'
# Preserve any user-selected config_path (absolute or relative, even if subscription file is temporarily absent).
if [ -z "$CUR_CFG" ]; then
  uci set openclash.config.config_path='/etc/openclash/config/template.yaml'
fi
uci set openclash.config.cn_port='9090'
uci set openclash.config.default_dashboard='metacubexd'
uci set openclash.config.dashboard_forward_ssl='0'
uci set openclash.config.operation_mode='fake-ip'
uci set openclash.config.en_mode='fake-ip'
uci set openclash.config.enable_redirect_dns='1'
uci set openclash.config.redirect_dns='0'
uci set openclash.config.cachesize_dns='0'
uci set openclash.config.dnsmasq_noresolv='0'
uci set openclash.config.intranet_allowed='1'
uci set openclash.config.enable='1'
uci commit openclash

/etc/init.d/openclash enable
/etc/init.d/openclash restart
