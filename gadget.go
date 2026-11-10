package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
)

// FIDO2 HID report descriptor (usage page 0xF1D0)
var fidoReportDesc = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (U2F HID Authenticator Device)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, //   Usage (Input Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x81, 0x02, //   Input (Data, Var, Abs)
	0x09, 0x21, //   Usage (Output Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x91, 0x02, //   Output (Data, Var, Abs)
	0xC0, //   End Collection
}

func findHIDDevice() (string, error) {
	matches, _ := filepath.Glob("/dev/hidg*")
	if len(matches) == 0 {
		return "", fmt.Errorf("no /dev/hidg* device found")
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches[0], nil
}

func setHIDPermissions(dev string) error {
	return exec.Command("chmod", "666", dev).Run()
}
