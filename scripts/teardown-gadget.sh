#!/system/bin/sh
# teardown-gadget.sh — Remove FIDO2 HID function from Android USB gadget
# Must run as root on the device.

GADGET="/config/usb_gadget/g1"
HID_FUNC="hid.usb0"
CONFIG_DIR="${GADGET}/configs"

echo "[1] Stopping adbd..."
stop adbd
sleep 1

echo "[2] Unbinding UDC..."
echo "" > "${GADGET}/UDC"
sleep 1

echo "[3] Removing HID from config..."
for cfg in ${CONFIG_DIR}/*/; do
    rm -f "${cfg}${HID_FUNC}"
done

echo "[4] Removing HID function..."
rmdir "${GADGET}/functions/${HID_FUNC}" 2>/dev/null

echo "[5] Rebinding UDC..."
echo "musb-hdrc" > "${GADGET}/UDC"
sleep 1

echo "[6] Restarting adbd..."
start adbd

echo "Done! Normal USB restored."
