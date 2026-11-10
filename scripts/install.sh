#!/bin/bash
# clave installer — downloads the latest release and pushes to a connected Android device.
# Usage: curl -sL https://raw.githubusercontent.com/thekeenest/clave/main/scripts/install.sh | bash
set -e

REPO="thekeenest/clave"
BINARY="clave-arm64"
DEVICE_PATH="/data/local/tmp/clave"

echo "=== clave installer ==="

# Check adb
if ! command -v adb &>/dev/null; then
    echo "ERROR: adb not found. Install Android platform-tools first."
    exit 1
fi

# Check device connected
if ! adb devices 2>/dev/null | grep -q "device$"; then
    echo "ERROR: No Android device connected (or not authorized)."
    echo "Connect your phone via USB and allow USB debugging."
    exit 1
fi

# Check root
if ! adb shell "id" 2>/dev/null | grep -q "uid=0"; then
    echo "Switching to root..."
    adb root >/dev/null 2>&1
    sleep 2
fi

# Check kernel HID support
echo "Checking kernel support..."
HID_SUPPORT=$(adb shell "zcat /proc/config.gz 2>/dev/null | grep CONFIG_USB_CONFIGFS_F_HID" 2>/dev/null || true)
if echo "$HID_SUPPORT" | grep -q "=y"; then
    echo "  CONFIG_USB_CONFIGFS_F_HID=y ✓"
else
    echo "  WARNING: CONFIG_USB_CONFIGFS_F_HID not found."
    echo "  Your kernel may not support USB HID gadget."
    echo "  LineageOS 20+ kernels usually have this built in."
fi

# Download latest release
echo "Downloading latest clave binary..."
TMPFILE=$(mktemp)
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"
if command -v curl &>/dev/null; then
    curl -sL "$DOWNLOAD_URL" -o "$TMPFILE"
elif command -v wget &>/dev/null; then
    wget -q "$DOWNLOAD_URL" -O "$TMPFILE"
else
    echo "ERROR: curl or wget required"
    exit 1
fi

SIZE=$(wc -c < "$TMPFILE" | tr -d ' ')
if [ "$SIZE" -lt 100000 ]; then
    echo "ERROR: Download failed (file too small: ${SIZE} bytes)."
    echo "Check: https://github.com/${REPO}/releases"
    rm -f "$TMPFILE"
    exit 1
fi
echo "  Downloaded ${SIZE} bytes"

# Push to device
echo "Pushing to device..."
adb push "$TMPFILE" "$DEVICE_PATH" >/dev/null
adb shell "chmod 755 $DEVICE_PATH"
rm -f "$TMPFILE"

# Verify
VERSION=$(adb shell "$DEVICE_PATH version" 2>/dev/null || true)
if [ -n "$VERSION" ]; then
    echo "  Installed: $VERSION"
else
    echo "  Binary pushed to $DEVICE_PATH"
fi

echo ""
echo "=== Install complete ==="
echo ""
echo "Start clave:"
echo "  adb shell $DEVICE_PATH serve -password YOUR_PASSWORD"
echo ""
echo "Then plug USB into your computer and register on any WebAuthn site."
echo "Press Volume Down on the phone to approve each request."
