#!/bin/bash
# clavectl.sh — Control clave FIDO2 security key daemon on Android device via ADB
set -e

BINARY_NAME="clave"
DEVICE_BIN="/data/local/tmp/${BINARY_NAME}"
DEVICE_STORE="/data/local/tmp/clave-keys.enc"
DEVICE_PID="/data/local/tmp/clave.pid"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"

# Read password from file if available, otherwise prompt
get_password() {
    local PW_FILE="$HOME/android/.pw"
    if [ -f "$PW_FILE" ]; then
        cat "$PW_FILE"
    else
        read -s -p "Enter FIDO2 key store password: " pw
        echo >&2
        echo "$pw"
    fi
}

build() {
    echo "Building fido2-key for Android arm64..."
    mkdir -p "$BUILD_DIR"
    cd "$PROJECT_DIR"
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "${BUILD_DIR}/${BINARY_NAME}" .
    ls -lh "${BUILD_DIR}/${BINARY_NAME}"
    echo "Build complete."
}

push() {
    echo "Pushing binary to device..."
    adb root >/dev/null 2>&1
    adb push "${BUILD_DIR}/${BINARY_NAME}" "$DEVICE_BIN"
    adb shell "chmod 755 ${DEVICE_BIN}"
    echo "Binary pushed."
}

start() {
    local PASSWORD
    PASSWORD=$(get_password)
    local AUTO_APPROVE=""
    if [ "$1" = "--auto-approve" ]; then
        AUTO_APPROVE="-auto-approve"
        echo "WARNING: Auto-approve mode — user presence check DISABLED"
    fi

    adb root >/dev/null 2>&1
    sleep 1

    # Check if already running
    if adb shell "test -f ${DEVICE_PID} && kill -0 \$(cat ${DEVICE_PID}) 2>/dev/null" 2>/dev/null; then
        echo "FIDO2 daemon is already running. Stop it first."
        exit 1
    fi

    # Ensure HID gadget is set up
    if ! adb shell "ls /dev/hidg* 2>/dev/null" | grep -q hidg; then
        echo "Setting up HID gadget..."
        adb push "${SCRIPT_DIR}/hid-setup.sh" /data/local/tmp/hid-setup.sh >/dev/null
        adb shell "su -c 'nohup sh /data/local/tmp/hid-setup.sh &'"
        echo "Waiting for gadget setup + ADB reconnect..."
        sleep 15
        for i in $(seq 1 20); do
            adb devices 2>/dev/null | grep -q device$ && break
            sleep 2
        done
        adb root >/dev/null 2>&1
        sleep 1
    fi

    # Set HID device permissions
    adb shell "chmod 666 /dev/hidg* 2>/dev/null"

    echo "Starting FIDO2 daemon..."
    adb shell "nohup ${DEVICE_BIN} serve -password '${PASSWORD}' -store ${DEVICE_STORE} ${AUTO_APPROVE} > /data/local/tmp/fido2.log 2>&1 & echo \$! > ${DEVICE_PID}"
    sleep 3

    if adb shell "kill -0 \$(cat ${DEVICE_PID}) 2>/dev/null"; then
        echo "FIDO2 daemon started (PID: $(adb shell "cat ${DEVICE_PID}"))"
        echo ""
        echo "=== FIDO2 Security Key ACTIVE ==="
        echo "  1. Connect phone to computer via USB"
        echo "  2. Press Volume Down on phone to approve requests"
        echo "  3. Run '$0 stop' to deactivate"
        echo ""
        echo "Recent log:"
        adb shell "tail -20 /data/local/tmp/fido2.log"
    else
        echo "ERROR: Daemon failed to start. Log:"
        adb shell "cat /data/local/tmp/fido2.log"
        exit 1
    fi
}

stop() {
    echo "Stopping FIDO2 daemon..."
    adb root >/dev/null 2>&1
    if adb shell "test -f ${DEVICE_PID}" 2>/dev/null; then
        adb shell "kill \$(cat ${DEVICE_PID}) 2>/dev/null || true"
        adb shell "rm -f ${DEVICE_PID}"
    fi
    adb shell "pkill -f 'fido2-key serve' 2>/dev/null || true"
    echo "FIDO2 daemon stopped (HID gadget left active for quick restart)."
    echo "Run '$0 teardown' to fully remove the gadget."
}

teardown() {
    echo "Removing HID gadget..."
    adb root >/dev/null 2>&1
    adb push "${SCRIPT_DIR}/teardown-gadget.sh" /data/local/tmp/teardown-gadget.sh >/dev/null
    adb shell "su -c 'nohup sh /data/local/tmp/teardown-gadget.sh &'"
    echo "Waiting for ADB reconnect..."
    sleep 10
    for i in $(seq 1 20); do
        adb devices 2>/dev/null | grep -q device$ && break
        sleep 2
    done
    echo "Normal USB restored."
}

status() {
    adb root >/dev/null 2>&1
    if adb shell "test -f ${DEVICE_PID} && kill -0 \$(cat ${DEVICE_PID}) 2>/dev/null" 2>/dev/null; then
        local PID
        PID=$(adb shell "cat ${DEVICE_PID}")
        echo "FIDO2 daemon: RUNNING (PID: $PID)"
        echo ""
        echo "Recent log:"
        adb shell "tail -10 /data/local/tmp/fido2.log"
    else
        echo "FIDO2 daemon: STOPPED"
    fi
    echo ""
    echo "HID device:"
    adb shell "ls -la /dev/hidg* 2>/dev/null || echo '  not present'"
    echo ""
    echo "USB gadget functions:"
    adb shell "ls /config/usb_gadget/g1/configs/*/hid* 2>/dev/null || echo '  no HID function'"
}

log() {
    adb shell "cat /data/local/tmp/fido2.log"
}

logfollow() {
    adb shell "tail -f /data/local/tmp/fido2.log"
}

list_creds() {
    local PASSWORD
    PASSWORD=$(get_password)
    adb root >/dev/null 2>&1
    adb shell "${DEVICE_BIN} list -password '${PASSWORD}' -store ${DEVICE_STORE}"
}

backup() {
    local BACKUP_FILE="${1:-fido2-backup-$(date +%Y%m%d).enc}"
    echo "Pulling encrypted key store..."
    adb pull "${DEVICE_STORE}" "$BACKUP_FILE" 2>/dev/null || {
        echo "No key store found on device (no credentials yet)"
        exit 1
    }
    echo "Backup saved to: $BACKUP_FILE"
    echo "This file is AES-256-GCM encrypted with your password."
    echo "KEEP IT SAFE — losing this + the device = losing your keys."
}

restore() {
    local BACKUP_FILE="$1"
    if [ -z "$BACKUP_FILE" ] || [ ! -f "$BACKUP_FILE" ]; then
        echo "Usage: $0 restore <backup-file>"
        exit 1
    fi
    echo "Pushing key store backup to device..."
    adb root >/dev/null 2>&1
    adb push "$BACKUP_FILE" "$DEVICE_STORE"
    adb shell "chmod 600 ${DEVICE_STORE}"
    echo "Key store restored. Restart daemon to use."
}

check_kernel() {
    adb root >/dev/null 2>&1
    echo "Checking kernel USB HID support..."
    local result
    result=$(adb shell "zcat /proc/config.gz 2>/dev/null | grep CONFIG_USB_CONFIGFS_F_HID" 2>/dev/null)
    if echo "$result" | grep -q "=y"; then
        echo "  CONFIG_USB_CONFIGFS_F_HID=y"
    else
        echo "  CONFIG_USB_CONFIGFS_F_HID NOT FOUND"
        echo "  Custom kernel with HID support is required!"
        exit 1
    fi

    echo ""
    echo "USB gadget configfs:"
    adb shell "ls /config/usb_gadget/ 2>/dev/null || echo '  not mounted'"
    echo ""
    echo "UDC controllers:"
    adb shell "ls /sys/class/udc/ 2>/dev/null || echo '  none'"
}

deploy() {
    build
    push
    echo ""
    echo "Deployment complete. Run '$0 start' to activate."
}

case "${1:-}" in
    build)      build ;;
    push)       push ;;
    deploy)     deploy ;;
    start)      start "$2" ;;
    stop)       stop ;;
    teardown)   teardown ;;
    status)     status ;;
    log)        log ;;
    logf)       logfollow ;;
    list)       list_creds ;;
    backup)     backup "$2" ;;
    restore)    restore "$2" ;;
    check)      check_kernel ;;
    *)
        echo "clavectl.sh — clave FIDO2 Security Key Controller"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Setup:"
        echo "  build    Build arm64 binary"
        echo "  push     Push binary to device"
        echo "  deploy   Build + push"
        echo "  check    Verify kernel HID support"
        echo ""
        echo "Runtime:"
        echo "  start [--auto-approve]  Start FIDO2 key mode"
        echo "  stop                    Stop daemon (keeps HID gadget)"
        echo "  teardown                Remove HID gadget, restore normal USB"
        echo "  status                  Show daemon status"
        echo "  log                     Show daemon log"
        echo "  logf                    Follow daemon log"
        echo ""
        echo "Credentials:"
        echo "  list     List stored credentials"
        echo "  backup [file]   Download encrypted key backup"
        echo "  restore <file>  Upload key backup to device"
        ;;
esac
