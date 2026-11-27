#!/bin/sh
# F50 Pro (aicwf_sdio / AIC8800) Wi-Fi Repeater + Fail-Safe AP Manager
# Works around aicwf_sdio concurrent AP+STA vif-rename quirk and guarantees
# the local AP (F50Pro-OpenWrt) always recovers if upstream Wi-Fi is unreachable.

LOCK_DIR="/tmp/f50pro-repeater.lock"
STATE_FILE="/tmp/run/f50pro-repeater.state"
HOSTAPD_SRC="/var/run/hostapd-phy0.conf"
HOSTAPD_OUT="/var/run/hostapd-phy0-repeater.conf"
FAIL_TIMEOUT=25

log_msg() {
    logger -t f50pro-repeater "$1" 2>/dev/null || true
}

get_macs() {
    STA_MAC="$(tr '[:upper:]' '[:lower:]' < /sys/class/ieee80211/phy0/macaddress 2>/dev/null | tr -d ' \n\r')"
    [ -n "$STA_MAC" ] || STA_MAC="02:f5:00:00:00:01"
    local prefix last last_dec
    prefix="${STA_MAC%:*}"
    last="${STA_MAC##*:}"
    last_dec=$((0x$last ^ 1))
    AP_MAC="$(printf '%s:%02x' "$prefix" "$last_dec")"
}

acquire_lock() {
    local tries=0
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [ -f "$LOCK_DIR/pid" ]; then
            local oldpid
            oldpid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
            if [ -n "$oldpid" ] && ! kill -0 "$oldpid" 2>/dev/null; then
                rm -rf "$LOCK_DIR" 2>/dev/null || true
                continue
            fi
        fi
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && return 1
        sleep 1
    done
    echo "$$" > "$LOCK_DIR/pid"
    return 0
}

release_lock() {
    rm -rf "$LOCK_DIR" 2>/dev/null || true
}

write_state() {
    local mode="$1" reason="$2" ssid="$3" ch="$4"
    mkdir -p /tmp/run 2>/dev/null || true
    cat > "${STATE_FILE}.tmp" <<EOF
MODE=$mode
REASON=$reason
STA_SSID=$ssid
CHANNEL=$ch
UPDATED=$(date +%s)
EOF
    mv -f "${STATE_FILE}.tmp" "$STATE_FILE"
}

find_iface_by_mode() {
    local want="$1"
    ucode -e '
import * as uci from "uci";
let c = uci.cursor();
let want = ARGV[0];
let found = "";
c.foreach("wireless", "wifi-iface", (s) => {
    if (s.device != "radio0") return;
    if (s.mode != want) return;
    if (s.disabled == "1") return;
    if (!found || (want == "ap" && s[".name"] == "default_radio0"))
        found = s[".name"];
});
print(found);
' "$want" 2>/dev/null
}

get_sta_iface_dev() {
    iw dev 2>/dev/null | awk '
        /Interface / { iface=$2 }
        /type managed/ { print iface; exit }
    '
}

get_ap_iface_dev() {
    iw dev 2>/dev/null | awk '
        /Interface / {
            if (!found && iface && is_ap && has_ch && has_ssid && iface != "phy0-sta0") { print iface; found=1; exit }
            iface=$2; is_ap=0; has_ch=0; has_ssid=0
        }
        /type AP$/ { is_ap=1 }
        /channel [0-9]/ { has_ch=1 }
        /ssid / { has_ssid=1 }
        END {
            if (!found && iface && is_ap && has_ch && has_ssid && iface != "phy0-sta0") print iface
        }
    '
}

sta_is_linked() {
    local dev="$1"
    [ -n "$dev" ] || return 1
    iw dev "$dev" link 2>/dev/null | grep -q 'Connected to '
}

sta_channel() {
    local dev="$1"
    [ -n "$dev" ] || return 1
    iw dev "$dev" info 2>/dev/null | awk '/channel /{print $2; exit}'
}

ap_channel() {
    local dev="$1"
    [ -n "$dev" ] || return 1
    iw dev "$dev" info 2>/dev/null | awk '/channel /{print $2; exit}'
}

ap_client_count() {
    local dev
    dev="$(get_ap_iface_dev)"
    [ -n "$dev" ] || { echo 0; return; }
    iw dev "$dev" station dump 2>/dev/null | grep -c '^Station ' || true
}

build_hostapd_conf() {
    local ch="$1" hwmode="$2" ap_sec="$3" compat_mode="${4:-normal}" out_file="${5:-$HOSTAPD_OUT}"
    get_macs

    rm -f "${out_file}.tmp"
    if [ "$compat_mode" != "conservative" ] && [ -f "$HOSTAPD_SRC" ] && grep -q '^interface=' "$HOSTAPD_SRC" 2>/dev/null; then
        # Derive repeater/fallback hostapd config from netifd-generated hostapd-phy0.conf.
        # Strip channel/width-tied oper fields and cross-band VHT/HE options when switching to 2.4 GHz
        # so 5 GHz capabilities never cause hostapd to reject 2.4 GHz AP startup on aicwf_sdio.
        if [ "$hwmode" = "a" ]; then
            sed -e '/^start_disabled=/d' \
                -e '/^acs_/d' \
                -e '/^vht_oper_/d' \
                -e '/^he_oper_/d' \
                -e '/^op_class=/d' \
                -e '/^basic_rates=/d' \
                -e '/^supported_rates=/d' \
                -e "s/^channel=.*/channel=$ch/" \
                -e "s/^hw_mode=.*/hw_mode=a/" \
                -e 's/^ht_capab=.*/ht_capab=[SHORT-GI-20]/' \
                -e "s/^bssid=.*/bssid=$AP_MAC/" \
                "$HOSTAPD_SRC" > "${out_file}.tmp" || return 1
        else
            sed -e '/^start_disabled=/d' \
                -e '/^acs_/d' \
                -e '/^vht_oper_/d' \
                -e '/^he_oper_/d' \
                -e '/^op_class=/d' \
                -e '/^ieee80211ac=/d' \
                -e '/^vht_capab=/d' \
                -e '/^ieee80211ax=/d' \
                -e '/^he_/d' \
                -e "s/^channel=.*/channel=$ch/" \
                -e "s/^hw_mode=.*/hw_mode=g/" \
                -e 's/^ht_capab=.*/ht_capab=[SHORT-GI-20]/' \
                -e "s/^bssid=.*/bssid=$AP_MAC/" \
                "$HOSTAPD_SRC" > "${out_file}.tmp" || return 1
        fi
        [ -s "${out_file}.tmp" ] || return 1
        chown root:network "${out_file}.tmp" 2>/dev/null || true
        chmod 640 "${out_file}.tmp" 2>/dev/null || true
        mv -f "${out_file}.tmp" "$out_file" || return 1
        return 0
    fi

    # Conservative fallback generator directly from UCI (safe minimal HT20 config, never forces unverified HE/LDPC flags)
    ucode -e '
import * as uci from "uci";
import * as fs from "fs";
let c = uci.cursor();
let ch = ARGV[0], hw = ARGV[1], sec = ARGV[2], bssid = ARGV[3], out = ARGV[4];
let ssid = c.get("wireless", sec, "ssid") || "F50Pro-OpenWrt";
let enc = c.get("wireless", sec, "encryption") || "psk2";
let key = c.get("wireless", sec, "key") || "";
let country = c.get("wireless", "radio0", "country") || "CN";
if (enc != "none" && length(key) < 8) {
    warn("f50pro-repeater: refusing to start fallback AP with invalid/missing key for encryption=" + enc + "\n");
    exit(1);
}
let lines = [
    "driver=nl80211",
    "country_code=" + country,
    "ieee80211d=1",
    "hw_mode=" + hw,
    "channel=" + ch,
    "ieee80211n=1",
    "ht_capab=[SHORT-GI-20]",
    "interface=phy0-ap0",
    "bssid=" + bssid,
    "ctrl_interface=/var/run/hostapd",
    "bridge=br-lan",
    "ssid=" + ssid,
    "utf8_ssid=1",
    "wmm_enabled=1",
    "ignore_broadcast_ssid=0",
    "disassoc_low_ack=0"
];
if (enc != "none") {
    push(lines, "wpa=2");
    push(lines, "wpa_passphrase=" + key);
    push(lines, "wpa_pairwise=CCMP");
    if (enc == "sae") {
        push(lines, "wpa_key_mgmt=SAE");
        push(lines, "ieee80211w=2");
    } else if (enc == "sae-mixed") {
        push(lines, "wpa_key_mgmt=WPA-PSK SAE");
        push(lines, "ieee80211w=1");
    } else {
        push(lines, "wpa_key_mgmt=WPA-PSK");
        push(lines, "ieee80211w=0");
    }
}
if (!fs.writefile(out, join("\n", lines) + "\n")) exit(1);
' "$ch" "$hwmode" "$ap_sec" "$AP_MAC" "${out_file}.tmp" 2>/dev/null || return 1
    [ -s "${out_file}.tmp" ] || return 1
    chown root:network "${out_file}.tmp" 2>/dev/null || true
    chmod 640 "${out_file}.tmp" 2>/dev/null || true
    mv -f "${out_file}.tmp" "$out_file" || return 1
    return 0
}

_apply_hostapd_conf() {
    local ch="$1"
    [ -s "$HOSTAPD_OUT" ] || return 1
    ubus call hostapd config_set '{"phy":"phy0","config":"","prev_config":""}' >/dev/null 2>&1 || true
    sleep 1
    if ! iw dev phy0-ap0 info >/dev/null 2>&1; then
        iw phy phy0 interface add phy0-ap0 type __ap >/dev/null 2>&1 || return 1
    fi
    ubus call hostapd config_set "{\"phy\":\"phy0\",\"config\":\"$HOSTAPD_OUT\",\"prev_config\":\"\"}" >/dev/null 2>&1 || return 1

    local w=0 ap_dev="" cur_ch=""
    while [ "$w" -lt 8 ]; do
        ap_dev="$(get_ap_iface_dev)"
        if [ -n "$ap_dev" ]; then
            cur_ch="$(ap_channel "$ap_dev")"
            if [ -z "$ch" ] || { [ -n "$cur_ch" ] && [ "$cur_ch" = "$ch" ]; }; then
                if [ ! -e "/sys/class/net/br-lan/brif/$ap_dev" ]; then
                    if ! ip link set "$ap_dev" master br-lan 2>/dev/null; then
                        log_msg "WARN: failed adding $ap_dev to br-lan"
                    fi
                fi
                [ -e "/sys/class/net/br-lan/brif/$ap_dev" ] && return 0
            fi
        fi
        w=$((w + 1))
        sleep 1
    done
    return 1
}

start_ap_on_channel() {
    local ch="$1" hwmode="$2" ap_sec="$3"
    local had_prev=0
    if [ -s "${HOSTAPD_OUT}.prev" ]; then
        had_prev=1
    elif [ -s "$HOSTAPD_OUT" ]; then
        cp -f "$HOSTAPD_OUT" "${HOSTAPD_OUT}.prev" 2>/dev/null && had_prev=1
    elif [ -s "$HOSTAPD_SRC" ]; then
        cp -f "$HOSTAPD_SRC" "${HOSTAPD_OUT}.prev" 2>/dev/null && had_prev=1
    fi

    if build_hostapd_conf "$ch" "$hwmode" "$ap_sec" "normal" "${HOSTAPD_OUT}.cand" && mv -f "${HOSTAPD_OUT}.cand" "$HOSTAPD_OUT" && _apply_hostapd_conf "$ch"; then
        rm -f "${HOSTAPD_OUT}.prev" "${HOSTAPD_OUT}.cand"
        return 0
    fi
    rm -f "${HOSTAPD_OUT}.cand"

    log_msg "Primary AP config failed on ch=$ch ($hwmode); retrying with conservative HT20 fallback"
    if build_hostapd_conf "$ch" "$hwmode" "$ap_sec" "conservative" "${HOSTAPD_OUT}.cand" && mv -f "${HOSTAPD_OUT}.cand" "$HOSTAPD_OUT" && _apply_hostapd_conf "$ch"; then
        rm -f "${HOSTAPD_OUT}.prev" "${HOSTAPD_OUT}.cand"
        return 0
    fi
    rm -f "${HOSTAPD_OUT}.cand"

    if [ "$had_prev" = "1" ] && [ -s "${HOSTAPD_OUT}.prev" ]; then
        if mv -f "${HOSTAPD_OUT}.prev" "$HOSTAPD_OUT" 2>/dev/null && _apply_hostapd_conf ""; then
            log_msg "Restored previous AP config after failed channel switch"
        else
            log_msg "ERROR: failed to restore previous AP config after channel switch failure"
        fi
    else
        rm -f "${HOSTAPD_OUT}.prev"
    fi
    return 1
}

cmd_ensure_ap() {
    acquire_lock || return 0

    local ap_sec sta_sec sta_dev ch hwmode cur_ap cur_ch sta_ssid
    ap_sec="$(find_iface_by_mode ap)"
    if [ -z "$ap_sec" ]; then
        release_lock
        return 0
    fi
    sta_sec="$(find_iface_by_mode sta)"
    sta_ssid=""
    [ -n "$sta_sec" ] && sta_ssid="$(uci -q get "wireless.$sta_sec.ssid")"

    sta_dev="$(get_sta_iface_dev)"
    if ! sta_is_linked "$sta_dev"; then
        release_lock
        return 0
    fi

    ch="$(sta_channel "$sta_dev")"
    if [ -z "$ch" ]; then
        release_lock
        return 0
    fi
    if [ "$ch" -gt 14 ] 2>/dev/null; then
        hwmode="a"
    else
        hwmode="g"
    fi

    cur_ap="$(get_ap_iface_dev)"
    if [ -n "$cur_ap" ]; then
        cur_ch="$(ap_channel "$cur_ap")"
        if [ -n "$cur_ch" ] && [ "$cur_ch" = "$ch" ]; then
            if [ ! -e "/sys/class/net/br-lan/brif/$cur_ap" ]; then
                ip link set "$cur_ap" master br-lan 2>/dev/null || true
            fi
            if [ -e "/sys/class/net/br-lan/brif/$cur_ap" ]; then
                write_state "repeater" "ok" "$sta_ssid" "$ch"
                release_lock
                return 0
            fi
            log_msg "WARN: active AP $cur_ap not attached to br-lan; recreating AP"
        fi
    fi

    log_msg "Starting concurrent AP phy0-ap0 on ch=$ch (hw_mode=$hwmode) alongside $sta_dev"
    if start_ap_on_channel "$ch" "$hwmode" "$ap_sec"; then
        write_state "repeater" "ok" "$sta_ssid" "$ch"
        log_msg "Concurrent AP phy0-ap0 active on ch=$ch"
        release_lock
        return 0
    fi
    log_msg "Failed to start concurrent AP phy0-ap0 on ch=$ch"
    release_lock
    return 1
}

cmd_fallback_ap() {
    local reason="${1:-sta_timeout}"
    acquire_lock || return 0

    local ap_sec sta_sec sta_ssid sta_dev band ch hwmode
    ap_sec="$(find_iface_by_mode ap)"
    if [ -z "$ap_sec" ]; then
        release_lock
        return 0
    fi
    sta_sec="$(find_iface_by_mode sta)"
    sta_ssid=""
    [ -n "$sta_sec" ] && sta_ssid="$(uci -q get "wireless.$sta_sec.ssid")"

    log_msg "Entering Fail-Safe AP mode (reason=$reason)"

    # Snapshot last active AP config BEFORE generating candidate or tearing down hostapd.
    rm -f "${HOSTAPD_OUT}.prev" "${HOSTAPD_OUT}.cand"
    if [ -s "$HOSTAPD_OUT" ]; then
        cp -f "$HOSTAPD_OUT" "${HOSTAPD_OUT}.prev" 2>/dev/null || true
    elif [ -s "$HOSTAPD_SRC" ]; then
        cp -f "$HOSTAPD_SRC" "${HOSTAPD_OUT}.prev" 2>/dev/null || true
    fi

    # Pick concrete non-DFS channel & pre-validate candidate into separate file BEFORE tearing down active hostapd.
    band="$(uci -q get wireless.radio0.band)"
    if [ "$band" = "5g" ]; then
        ch="36"
        hwmode="a"
    else
        ch="11"
        hwmode="g"
    fi
    if ! build_hostapd_conf "$ch" "$hwmode" "$ap_sec" "normal" "${HOSTAPD_OUT}.cand" && ! build_hostapd_conf "11" "g" "$ap_sec" "conservative" "${HOSTAPD_OUT}.cand"; then
        rm -f "${HOSTAPD_OUT}.prev" "${HOSTAPD_OUT}.cand"
        log_msg "ERROR: Refusing Fail-Safe AP teardown because no valid candidate hostapd config could be generated"
        release_lock
        return 1
    fi
    rm -f "${HOSTAPD_OUT}.cand"

    # Stop wpa_supplicant and remove any phy0-sta0 (even if renamed to type AP by aicwf_sdio) at runtime only (UCI preserved!)
    ubus call wpa_supplicant config_set '{"phy":"phy0","config":[]}' >/dev/null 2>&1 || true
    ubus call hostapd config_set '{"phy":"phy0","config":"","prev_config":""}' >/dev/null 2>&1 || true
    sta_dev="$(get_sta_iface_dev)"
    if [ -n "$sta_dev" ]; then
        ip link set "$sta_dev" down 2>/dev/null || true
        iw dev "$sta_dev" del 2>/dev/null || true
    fi
    if iw dev phy0-sta0 info >/dev/null 2>&1; then
        ip link set phy0-sta0 down 2>/dev/null || true
        iw dev phy0-sta0 del 2>/dev/null || true
    fi
    sleep 1

    if start_ap_on_channel "$ch" "$hwmode" "$ap_sec"; then
        write_state "fallback_ap" "$reason" "$sta_ssid" "$ch"
        log_msg "Fail-Safe AP phy0-ap0 active on ch=$ch ($hwmode)"
        release_lock
        return 0
    fi
    # Last-resort retry on 2.4 GHz ch 11
    if [ "$hwmode" != "g" ] && start_ap_on_channel "11" "g" "$ap_sec"; then
        write_state "fallback_ap" "$reason" "$sta_ssid" "11"
        log_msg "Fail-Safe AP phy0-ap0 active on 2.4GHz ch=11 fallback"
        release_lock
        return 0
    fi
    log_msg "ERROR: Fail-Safe AP failed to start"
    release_lock
    return 1
}

ssid_visible_on_air() {
    local target="$1"
    [ -n "$target" ] || return 1
    ucode -e '
import * as fs from "fs";
let target = ARGV[0];
let p = fs.popen("iw dev phy0-ap0 scan ap-force 2>/dev/null", "r");
if (!p) exit(1);
let out = p.read("all") || "";
p.close();
function unesc(s) {
    return replace(s, /\\x([0-9a-fA-F]{2})/g, (m, h) => chr(hex(h)));
}
for (let line in split(out, "\n")) {
    let m = match(line, /^\s*SSID: (.*)$/);
    if (m) {
        if (m[1] == target || unesc(m[1]) == target) exit(0);
    }
}
exit(1);
' "$target" 2>/dev/null
}

cmd_trigger_reload() {
    local sta_sec sta_ssid
    sta_sec="$(find_iface_by_mode sta)"
    sta_ssid=""
    [ -n "$sta_sec" ] && sta_ssid="$(uci -q get "wireless.$sta_sec.ssid")"
    if [ -n "$sta_sec" ]; then
        write_state "connecting" "user_apply" "$sta_ssid" ""
    else
        write_state "ap_only" "user_apply" "" ""
    fi
    wifi down >/dev/null 2>&1 || true
    sleep 1
    wifi up >/dev/null 2>&1 || true
}

cmd_watchdog() {
    log_msg "Watchdog started (fail_timeout=${FAIL_TIMEOUT}s)"
    local fail_secs=0 fallback_secs=0 retry_backoff=90 ap_missing_secs=0

    while true; do
        sleep 5

        if [ ! -d /sys/class/ieee80211/phy0 ] || [ "$(uci -q get wireless.radio0.disabled)" = "1" ]; then
            fail_secs=0
            ap_missing_secs=0
            continue
        fi

        local sta_sec ap_sec sta_ssid sta_dev ap_dev
        sta_sec="$(find_iface_by_mode sta)"
        ap_sec="$(find_iface_by_mode ap)"
        sta_dev="$(get_sta_iface_dev)"
        ap_dev="$(get_ap_iface_dev)"

        # Case 0: Pure AP mode (no enabled STA in UCI)
        if [ -z "$sta_sec" ]; then
            fail_secs=0
            fallback_secs=0
            retry_backoff=90
            if [ -n "$ap_sec" ]; then
                if [ -n "$ap_dev" ]; then
                    ap_missing_secs=0
                    write_state "ap_only" "ok" "" "$(ap_channel "$ap_dev")"
                else
                    ap_missing_secs=$((ap_missing_secs + 5))
                    if [ "$ap_missing_secs" -ge 15 ]; then
                        ap_missing_secs=0
                        cmd_fallback_ap "ap_only_heal" || true
                    fi
                fi
            fi
            continue
        fi

        ap_missing_secs=0
        sta_ssid="$(uci -q get "wireless.$sta_sec.ssid")"

        # Case 1: STA is linked
        if sta_is_linked "$sta_dev"; then
            fail_secs=0
            fallback_secs=0
            retry_backoff=90
            if [ -n "$ap_sec" ]; then
                local st_ch ap_ch
                st_ch="$(sta_channel "$sta_dev")"
                ap_ch=""
                [ -n "$ap_dev" ] && ap_ch="$(ap_channel "$ap_dev")"
                if [ -z "$ap_dev" ] || [ -z "$ap_ch" ] || [ "$ap_ch" != "$st_ch" ] || [ ! -e "/sys/class/net/br-lan/brif/$ap_dev" ]; then
                    cmd_ensure_ap || true
                else
                    write_state "repeater" "ok" "$sta_ssid" "$st_ch"
                fi
            else
                write_state "repeater" "sta_only" "$sta_ssid" "$(sta_channel "$sta_dev")"
            fi
            continue
        fi

        # Case 2: Currently in Fail-Safe AP mode (AP is up, STA vif removed)
        if [ -n "$ap_dev" ] && [ -z "$sta_dev" ]; then
            fail_secs=0
            local clients
            clients="$(ap_client_count)"
            if [ "${clients:-0}" -gt 0 ]; then
                # Never kick off a connected phone/PC in Fail-Safe AP mode!
                fallback_secs=0
            else
                fallback_secs=$((fallback_secs + 5))
                if [ "$fallback_secs" -ge "$retry_backoff" ]; then
                    fallback_secs=0
                    if ssid_visible_on_air "$sta_ssid"; then
                        log_msg "Configured upstream Wi-Fi detected while 0 clients connected; retrying repeater"
                        retry_backoff=$((retry_backoff * 2))
                        [ "$retry_backoff" -gt 300 ] && retry_backoff=300
                        cmd_trigger_reload
                    fi
                fi
            fi
            continue
        fi

        # Case 3: STA is trying to connect (or lost link)
        fail_secs=$((fail_secs + 5))
        if [ -z "$ap_dev" ]; then
            write_state "connecting" "waiting_sta" "$sta_ssid" ""
        fi
        if [ "$fail_secs" -ge "$FAIL_TIMEOUT" ]; then
            fail_secs=0
            fallback_secs=0
            if [ -n "$ap_sec" ]; then
                cmd_fallback_ap "sta_timeout" || true
            fi
        fi
    done
}

case "${1:-}" in
    ensure_ap) cmd_ensure_ap ;;
    fallback_ap) cmd_fallback_ap "${2:-manual}" ;;
    trigger_reload) cmd_trigger_reload ;;
    watchdog) cmd_watchdog ;;
    *)
        echo "Usage: $0 {ensure_ap|fallback_ap|trigger_reload|watchdog}" >&2
        exit 1
        ;;
esac
