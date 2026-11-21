#!/system/bin/sh
# Hardened ttyd login script: zero hardcoded fallback password.
# Accepts the UFI-TOOLS app login_token (hashed with app sha256) when set;
# otherwise ONLY accepts the per-device random SHA-256 hash provisioned in
# /data/adb/ufi-ttyd.sha256 (standard unsalted sha256sum). Fails closed if absent.

trap '' INT TSTP
umask 077

MAX_RETRIES=3
retry_count=0

PASS_FILE="/data/data/com.minikano.f50_sms/shared_prefs/kano_ZTE_store.xml"
PROVISIONED_HASH_FILE="/data/adb/ufi-ttyd.sha256"
SHA256_BIN="/data/data/com.minikano.f50_sms/files/sha256"

is_sha256_hex() {
    case "$1" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

load_expected_auth() {
    AUTH_SOURCE=""
    EXPECTED_HASH=""
    if [ -r "$PASS_FILE" ]; then
        h="$(grep '<string name="login_token">' "$PASS_FILE" \
            | sed -n 's/.*<string name="login_token">\([^<]*\)<\/string>.*/\1/p' \
            | head -n 1 | tr -d '\r\n ' | tr 'A-F' 'a-f')"
        if [ -n "$h" ] && is_sha256_hex "$h" && [ -x "$SHA256_BIN" ]; then
            AUTH_SOURCE="xml"
            EXPECTED_HASH="$h"
            return 0
        fi
    fi
    if [ -r "$PROVISIONED_HASH_FILE" ]; then
        h="$(head -n 1 "$PROVISIONED_HASH_FILE" | tr -d '\r\n ' | tr 'A-F' 'a-f')"
        if [ -n "$h" ] && is_sha256_hex "$h" && command -v sha256sum >/dev/null 2>&1; then
            AUTH_SOURCE="provisioned"
            EXPECTED_HASH="$h"
            return 0
        fi
    fi
    return 1
}

read_password() {
    prompt="$1"
    INPUT_RAW_PASS=""
    printf "%s" "$prompt" 1>&2
    if command -v stty >/dev/null 2>&1; then
        stty -echo 2>/dev/null
        if ! IFS= read -r INPUT_RAW_PASS; then
            stty echo 2>/dev/null
            printf "\n" 1>&2
            return 1
        fi
        stty echo 2>/dev/null
        printf "\n" 1>&2
    else
        if ! IFS= read -r INPUT_RAW_PASS; then
            printf "\n" 1>&2
            return 1
        fi
        printf "\n" 1>&2
    fi
    return 0
}

while true; do
    if ! load_expected_auth; then
        echo "Terminal login disabled: no valid password configured." 1>&2
        exit 1
    fi

    if ! read_password "Password: "; then
        exit 1
    fi
    input_raw_pass="$INPUT_RAW_PASS"
    if [ "$AUTH_SOURCE" = "xml" ]; then
        input_pass="$("$SHA256_BIN" "$input_raw_pass" | tr 'A-F' 'a-f')"
    else
        input_pass="$(printf '%s' "$input_raw_pass" | sha256sum | cut -d' ' -f1 | tr 'A-F' 'a-f')"
    fi

    if [ -n "$input_pass" ] && [ "$input_pass" = "$EXPECTED_HASH" ]; then
        echo "Login successful!"
        exec /system/bin/sh
    else
        retry_count=$((retry_count + 1))
        echo "Incorrect password! Attempt ${retry_count}/${MAX_RETRIES}"

        if [ "$retry_count" -ge "$MAX_RETRIES" ]; then
            echo "Too many failed attempts, exiting..."
            exit 1
        else
            sleep 1
        fi
    fi
done
