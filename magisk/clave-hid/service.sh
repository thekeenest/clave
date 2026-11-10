#!/system/bin/sh
# Clave FIDO2 HID — adds HID function to USB gadget after boot completes.
# Runs via Magisk service.sh (triggers at boot_completed, after USB is stable).

GADGET=/config/usb_gadget/g1
FUNC=$GADGET/functions/hid.usb0
CONFIG=$GADGET/configs/b.1
UDC_FILE=$GADGET/UDC
LOG=/data/local/tmp/clave-hid.log

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"; }

log "=== clave-hid service.sh start ==="

# Wait for UDC to be bound (should already be at boot_completed)
n=0
while [ -z "$(cat $UDC_FILE 2>/dev/null | tr -d '[:space:]')" ] && [ $n -lt 30 ]; do
    sleep 1
    n=$((n + 1))
done

UDC=$(cat $UDC_FILE 2>/dev/null | tr -d '[:space:]')
if [ -z "$UDC" ]; then
    log "ERROR: no UDC bound after 30s, aborting"
    exit 1
fi
log "UDC active: $UDC"

# If HID device already exists, just fix permissions and exit
if ls /dev/hidg* >/dev/null 2>&1; then
    chmod 666 /dev/hidg* 2>/dev/null
    log "HID device already present, permissions set"
    exit 0
fi

# Create HID function directory if needed
if [ ! -d "$FUNC" ]; then
    mkdir -p "$FUNC" 2>/dev/null
    if [ $? -ne 0 ]; then
        log "ERROR: cannot create $FUNC"
        exit 1
    fi
    log "Created HID function directory"
fi

# Configure HID function
cur_len=$(cat "$FUNC/report_length" 2>/dev/null | tr -d '[:space:]')
if [ "$cur_len" != "64" ]; then
    echo 0 > "$FUNC/protocol" 2>/dev/null
    echo 0 > "$FUNC/subclass" 2>/dev/null
    echo 64 > "$FUNC/report_length" 2>/dev/null
    printf '\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0' > "$FUNC/report_desc" 2>/dev/null
    log "Configured HID (protocol=0, subclass=0, report_length=64, FIDO descriptor)"
fi

# === CRITICAL SECTION: unbind → link → rebind ===
# ADB drops briefly during this window but reconnects automatically.
log "Unbinding UDC to add HID symlink..."
echo > "$UDC_FILE"
sleep 1

check=$(cat "$UDC_FILE" 2>/dev/null | tr -d '[:space:]')
if [ -n "$check" ]; then
    log "Unbind incomplete, retrying"
    echo > "$UDC_FILE"
    sleep 1
fi

# Create symlink if not present
if [ ! -L "$CONFIG/hid.usb0" ]; then
    ln -s "$FUNC" "$CONFIG/hid.usb0" 2>/dev/null
    if [ $? -ne 0 ]; then
        log "ERROR: symlink failed, rebinding without HID"
        echo "$UDC" > "$UDC_FILE"
        exit 1
    fi
    log "Linked hid.usb0 into config"
fi

# Rebind
echo "$UDC" > "$UDC_FILE"
sleep 1

check=$(cat "$UDC_FILE" 2>/dev/null | tr -d '[:space:]')
if [ -z "$check" ]; then
    log "Rebind failed, retrying"
    echo "$UDC" > "$UDC_FILE"
    sleep 2
fi
log "UDC rebound: $(cat $UDC_FILE 2>/dev/null | tr -d '[:space:]')"

# Wait for /dev/hidg* to appear
n=0
while ! ls /dev/hidg* >/dev/null 2>&1 && [ $n -lt 10 ]; do
    sleep 1
    n=$((n + 1))
done

if ls /dev/hidg* >/dev/null 2>&1; then
    chmod 666 /dev/hidg* 2>/dev/null
    log "SUCCESS: $(ls /dev/hidg* 2>/dev/null)"
else
    log "WARNING: no /dev/hidg* after rebind"
fi

log "=== clave-hid service.sh done ==="
