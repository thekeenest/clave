#!/system/bin/sh
# setup-gadget.sh — Add FIDO2 HID function to Android USB gadget
# Must run as root on the device. Launched detached from ADB.
# Usage: nohup sh setup-gadget.sh > /data/local/tmp/setup.log 2>&1 &

GADGET="/config/usb_gadget/g1"
HID_FUNC="hid.usb0"
HID_PATH="${GADGET}/functions/${HID_FUNC}"
CONFIG_DIR="${GADGET}/configs"
LOG="/data/local/tmp/setup.log"

echo "[0] Waiting 2s for ADB to detach..."
sleep 2

echo "[1] Stopping adbd..."
setprop sys.usb.ffs.ready 0
stop adbd
sleep 1

echo "[2] Unbinding UDC..."
echo "" > "${GADGET}/UDC"
sleep 1

echo "[3] Creating HID function..."
mkdir -p "${HID_PATH}"
echo 0 > "${HID_PATH}/protocol"
echo 0 > "${HID_PATH}/subclass"
echo 64 > "${HID_PATH}/report_length"

# FIDO2 HID Report Descriptor (usage page 0xF1D0)
printf '\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0' > "${HID_PATH}/report_desc"

echo "[4] Linking HID into config..."
# Find the active config
ACTIVE_CFG=$(ls -d ${CONFIG_DIR}/*/ 2>/dev/null | head -1)
if [ -z "$ACTIVE_CFG" ]; then
    echo "ERROR: No config found"
    echo "musb-hdrc" > "${GADGET}/UDC"
    start adbd
    exit 1
fi
ln -sf "${HID_PATH}" "${ACTIVE_CFG}/${HID_FUNC}"

echo "[5] Rebinding UDC..."
echo "musb-hdrc" > "${GADGET}/UDC"
sleep 1

echo "[6] Restarting adbd..."
start adbd
sleep 1

echo "[7] Setting permissions on /dev/hidg0..."
for i in 1 2 3 4 5; do
    if [ -e /dev/hidg0 ]; then
        chmod 666 /dev/hidg0
        echo "Done! /dev/hidg0 is ready."
        ls -la /dev/hidg0
        exit 0
    fi
    sleep 1
done

echo "WARNING: /dev/hidg0 not found after 5 seconds"
ls -la /dev/hidg* 2>/dev/null
exit 1
