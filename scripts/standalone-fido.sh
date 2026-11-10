#!/system/bin/sh
# Switch from composite ADB+HID to standalone FIDO2 HID gadget.
# ADB will be unavailable while this runs. After 120s, reverts to ADB mode.
# Usage: adb shell "nohup sh /data/local/tmp/standalone-fido.sh &"

LOG=/data/local/tmp/standalone-fido.log
exec > $LOG 2>&1
set -x

PW=$(cat /data/local/tmp/.fido2pw 2>/dev/null)
if [ -z "$PW" ]; then
    echo "ERROR: No password file at /data/local/tmp/.fido2pw"
    echo "Create it: echo 'YOUR_PASSWORD' > /data/local/tmp/.fido2pw"
    exit 1
fi

echo "=== Standalone FIDO2 mode $(date) ==="

# Kill existing daemon
pkill -f 'fido2-key serve' 2>/dev/null
sleep 1

# Save current UDC
UDC=$(cat /config/usb_gadget/g1/UDC 2>/dev/null)
echo "Current UDC: $UDC"

# Unbind existing gadget (drops ADB)
echo "" > /config/usb_gadget/g1/UDC
sleep 1

# Remove HID from g1 if linked
rm -f /config/usb_gadget/g1/configs/b.1/hid.usb0

# Create standalone FIDO2 gadget
GBASE=/config/usb_gadget/g_fido
mkdir -p $GBASE/strings/0x409
mkdir -p $GBASE/functions/hid.usb0
mkdir -p $GBASE/configs/c.1/strings/0x409

# FIDO2-specific identity
echo "0x1209" > $GBASE/idVendor
echo "0xF1D0" > $GBASE/idProduct
echo "0x0100" > $GBASE/bcdDevice
echo "0x0210" > $GBASE/bcdUSB
echo "OpenFIDO" > $GBASE/strings/0x409/manufacturer
echo "FIDO2 Security Key" > $GBASE/strings/0x409/product
echo "FIDO2-LANCELOT-001" > $GBASE/strings/0x409/serialnumber

# HID function
echo 0 > $GBASE/functions/hid.usb0/protocol
echo 0 > $GBASE/functions/hid.usb0/subclass
echo 64 > $GBASE/functions/hid.usb0/report_length
printf '\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0' > $GBASE/functions/hid.usb0/report_desc

# Config
echo 120 > $GBASE/configs/c.1/MaxPower
echo "FIDO2 Config" > $GBASE/configs/c.1/strings/0x409/configuration
ln -sf $GBASE/functions/hid.usb0 $GBASE/configs/c.1/hid.usb0

# Bind
echo "musb-hdrc" > $GBASE/UDC
echo "Standalone FIDO2 gadget bound"

sleep 2

# Find HID device
HIDDEV=$(ls /dev/hidg* 2>/dev/null | head -1)
if [ -z "$HIDDEV" ]; then
    echo "ERROR: No HID device found"
    # Restore ADB
    echo "" > $GBASE/UDC 2>/dev/null
    rm -f $GBASE/configs/c.1/hid.usb0 2>/dev/null
    echo "musb-hdrc" > /config/usb_gadget/g1/UDC
    exit 1
fi

chmod 666 "$HIDDEV"
echo "HID device: $HIDDEV"

# Start FIDO2 daemon
/data/local/tmp/fido2-key serve \
    -password "$PW" \
    -store /data/local/tmp/fido2-keys.enc \
    -auto-approve &
DAEMON_PID=$!
echo "Daemon PID: $DAEMON_PID"

# Wait 120 seconds for testing
echo "=== STANDALONE FIDO2 ACTIVE for 120s ==="
sleep 120

# Cleanup: kill daemon, restore ADB
echo "=== Restoring ADB mode ==="
kill $DAEMON_PID 2>/dev/null
sleep 1

# Unbind standalone
echo "" > $GBASE/UDC 2>/dev/null
rm -f $GBASE/configs/c.1/hid.usb0 2>/dev/null
rmdir $GBASE/configs/c.1/strings/0x409 2>/dev/null
rmdir $GBASE/configs/c.1 2>/dev/null
rmdir $GBASE/functions/hid.usb0 2>/dev/null
rmdir $GBASE/strings/0x409 2>/dev/null
rmdir $GBASE 2>/dev/null

# Rebind g1 with ADB
echo "musb-hdrc" > /config/usb_gadget/g1/UDC
echo "ADB restored"
