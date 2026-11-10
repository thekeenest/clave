#!/system/bin/sh
LOG=/data/local/tmp/hid-setup.log
exec > $LOG 2>&1
set -x

echo "=== HID Setup $(date) ==="

# Step 1: Stop adbd and unbind
echo "[1] Stopping adbd..."
setprop sys.usb.ffs.ready 0
stop adbd
sleep 1

echo "[2] Unbinding UDC..."
echo "" > /config/usb_gadget/g1/UDC
sleep 1

# Step 3: Configure HID function
echo "[3] Configuring HID function..."
mkdir -p /config/usb_gadget/g1/functions/hid.usb0
echo 0 > /config/usb_gadget/g1/functions/hid.usb0/protocol
echo 0 > /config/usb_gadget/g1/functions/hid.usb0/subclass
echo 64 > /config/usb_gadget/g1/functions/hid.usb0/report_length
printf '\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0' > /config/usb_gadget/g1/functions/hid.usb0/report_desc

# Step 4: Link HID function into config
echo "[4] Linking HID function..."
rm -f /config/usb_gadget/g1/configs/b.1/hid.usb0
ln -s /config/usb_gadget/g1/functions/hid.usb0 /config/usb_gadget/g1/configs/b.1/hid.usb0
echo "ln exit: $?"
ls -la /config/usb_gadget/g1/configs/b.1/

# Step 5: Restart adbd so it re-registers FunctionFS
echo "[5] Starting adbd..."
start adbd

# Step 6: Wait for FunctionFS to be ready
echo "[6] Waiting for FunctionFS ready..."
i=0
while [ $i -lt 20 ]; do
    READY=$(getprop sys.usb.ffs.ready)
    if [ "$READY" = "1" ]; then
        echo "FFS ready after ${i}s"
        break
    fi
    i=$((i + 1))
    sleep 1
done

# Step 7: Bind UDC
echo "[7] Binding UDC..."
echo "musb-hdrc" > /config/usb_gadget/g1/UDC
echo "UDC exit: $?"
cat /config/usb_gadget/g1/UDC
sleep 2

# Step 8: Check for hidg device
echo "[8] Checking for /dev/hidg*..."
i=0
while [ $i -lt 10 ]; do
    HIDDEV=$(ls /dev/hidg* 2>/dev/null | tail -1)
    if [ -c "$HIDDEV" ]; then
        chmod 666 "$HIDDEV"
        ls -la /dev/hidg*
        echo "=== SUCCESS: $HIDDEV ==="
        exit 0
    fi
    i=$((i + 1))
    sleep 1
done

echo "No hidg device found."
echo "=== FAILED ==="
