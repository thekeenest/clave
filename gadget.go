package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

const (
	gadgetBase    = "/config/usb_gadget/g_fido"
	hidFunc       = "hid.usb0"
	configName    = "b.1"
	defaultGadget = "/config/usb_gadget/g1"
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

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func writeFileStr(path, data string) error {
	return writeFile(path, []byte(data))
}

func gadgetSetup() error {
	// Unbind existing UDC first
	gadgetTeardown()

	dirs := []string{
		gadgetBase,
		filepath.Join(gadgetBase, "strings/0x409"),
		filepath.Join(gadgetBase, "functions", hidFunc),
		filepath.Join(gadgetBase, "configs", configName),
		filepath.Join(gadgetBase, "configs", configName, "strings/0x409"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// Device descriptors — generic FIDO2 authenticator identity
	writes := map[string]string{
		"idVendor":  "0x1209", // pid.codes open-source VID
		"idProduct": "0xF1D0", // FIDO-themed PID
		"bcdDevice": "0x0100",
		"bcdUSB":    "0x0210", // USB 2.1 for BOS descriptor
	}
	for name, val := range writes {
		if err := writeFileStr(filepath.Join(gadgetBase, name), val); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	strings := map[string]string{
		"serialnumber": "FIDO2-LANCELOT-001",
		"manufacturer": "OpenFIDO",
		"product":      "FIDO2 Security Key",
	}
	for name, val := range strings {
		if err := writeFileStr(filepath.Join(gadgetBase, "strings/0x409", name), val); err != nil {
			return fmt.Errorf("write string %s: %w", name, err)
		}
	}

	// HID function
	funcPath := filepath.Join(gadgetBase, "functions", hidFunc)
	if err := writeFileStr(filepath.Join(funcPath, "protocol"), "0"); err != nil {
		return fmt.Errorf("write protocol: %w", err)
	}
	if err := writeFileStr(filepath.Join(funcPath, "subclass"), "0"); err != nil {
		return fmt.Errorf("write subclass: %w", err)
	}
	if err := writeFileStr(filepath.Join(funcPath, "report_length"), "64"); err != nil {
		return fmt.Errorf("write report_length: %w", err)
	}
	if err := writeFile(filepath.Join(funcPath, "report_desc"), fidoReportDesc); err != nil {
		return fmt.Errorf("write report_desc: %w", err)
	}

	// Config
	cfgPath := filepath.Join(gadgetBase, "configs", configName)
	if err := writeFileStr(filepath.Join(cfgPath, "MaxPower"), "120"); err != nil {
		return fmt.Errorf("write MaxPower: %w", err)
	}
	if err := writeFileStr(filepath.Join(cfgPath, "strings/0x409/configuration"), "FIDO2 Config"); err != nil {
		return fmt.Errorf("write config string: %w", err)
	}

	// Symlink function into config
	symlink := filepath.Join(cfgPath, hidFunc)
	os.Remove(symlink)
	if err := os.Symlink(funcPath, symlink); err != nil {
		return fmt.Errorf("symlink: %w", err)
	}

	// Find and bind UDC
	udc, err := findUDC()
	if err != nil {
		return err
	}
	if err := writeFileStr(filepath.Join(gadgetBase, "UDC"), udc); err != nil {
		return fmt.Errorf("bind UDC %s: %w", udc, err)
	}

	fmt.Printf("USB HID gadget bound to %s\n", udc)
	return nil
}

func gadgetTeardown() {
	// Unbind UDC
	writeFileStr(filepath.Join(gadgetBase, "UDC"), "")

	// Remove symlink
	symlink := filepath.Join(gadgetBase, "configs", configName, hidFunc)
	os.Remove(symlink)

	// Remove dirs in reverse order (ignore errors — they may not exist)
	rmDirs := []string{
		filepath.Join(gadgetBase, "configs", configName, "strings/0x409"),
		filepath.Join(gadgetBase, "configs", configName),
		filepath.Join(gadgetBase, "functions", hidFunc),
		filepath.Join(gadgetBase, "strings/0x409"),
		gadgetBase,
	}
	for _, d := range rmDirs {
		os.Remove(d)
	}
}

func findUDC() (string, error) {
	entries, err := os.ReadDir("/sys/class/udc")
	if err != nil {
		return "", fmt.Errorf("list UDC: %w", err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no UDC found in /sys/class/udc")
	}
	return entries[0].Name(), nil
}

// disableCurrentGadget unbinds any existing USB gadget so we can reconfigure.
func disableCurrentGadget() {
	// Try to unbind the default Android gadget
	defaultGadget := "/config/usb_gadget/g1"
	udcPath := filepath.Join(defaultGadget, "UDC")
	if data, err := os.ReadFile(udcPath); err == nil && len(data) > 0 {
		writeFileStr(udcPath, "")
		fmt.Println("Unbound default Android USB gadget")
	}
}

// restoreDefaultGadget re-enables the default Android USB gadget.
func restoreDefaultGadget() {
	defaultGadget := "/config/usb_gadget/g1"
	udcPath := filepath.Join(defaultGadget, "UDC")

	// Check if it's already bound
	if data, err := os.ReadFile(udcPath); err == nil && len(data) > 1 {
		return
	}

	udc, err := findUDC()
	if err != nil {
		return
	}
	writeFileStr(udcPath, udc)
	fmt.Println("Restored default Android USB gadget")
}

// hidAlreadyActive returns true if our HID function is linked and a device exists.
func hidAlreadyActive() bool {
	symlink := filepath.Join(defaultGadget, "configs", configName, hidFunc)
	if _, err := os.Lstat(symlink); err != nil {
		return false
	}
	if dev, err := findHIDDevice(); err == nil && dev != "" {
		return true
	}
	return false
}

// addHIDToExistingGadget adds a FIDO HID function to the existing Android gadget
// instead of replacing it — this lets charging and ADB keep working.
func addHIDToExistingGadget() error {
	defaultGadget := "/config/usb_gadget/g1"

	// Check if default gadget exists
	if _, err := os.Stat(defaultGadget); err != nil {
		return fmt.Errorf("default gadget g1 not found: %w", err)
	}

	funcPath := filepath.Join(defaultGadget, "functions", hidFunc)

	// Create HID function if it doesn't exist
	if _, err := os.Stat(funcPath); err != nil {
		if err := os.MkdirAll(funcPath, 0755); err != nil {
			return fmt.Errorf("create HID function: %w", err)
		}
	}

	if err := writeFileStr(filepath.Join(funcPath, "protocol"), "0"); err != nil {
		return fmt.Errorf("write protocol: %w", err)
	}
	if err := writeFileStr(filepath.Join(funcPath, "subclass"), "0"); err != nil {
		return fmt.Errorf("write subclass: %w", err)
	}
	if err := writeFileStr(filepath.Join(funcPath, "report_length"), "64"); err != nil {
		return fmt.Errorf("write report_length: %w", err)
	}
	if err := writeFile(filepath.Join(funcPath, "report_desc"), fidoReportDesc); err != nil {
		return fmt.Errorf("write report_desc: %w", err)
	}

	return nil
}

// rebindGadgetWithHID unbinds the default gadget, links HID function, rebinds.
func rebindGadgetWithHID() error {
	defaultGadget := "/config/usb_gadget/g1"
	udcPath := filepath.Join(defaultGadget, "UDC")

	// Read current UDC
	udcData, err := os.ReadFile(udcPath)
	if err != nil {
		return fmt.Errorf("read UDC: %w", err)
	}
	udc := string(udcData)
	if len(udc) < 2 {
		u, err := findUDC()
		if err != nil {
			return err
		}
		udc = u
	}

	// Unbind
	writeFileStr(udcPath, "")

	// Add HID function
	if err := addHIDToExistingGadget(); err != nil {
		// Rebind without HID on failure
		writeFileStr(udcPath, udc)
		return err
	}

	// Find the active config directory
	cfgDir := filepath.Join(defaultGadget, "configs")
	configs, err := os.ReadDir(cfgDir)
	if err != nil || len(configs) == 0 {
		writeFileStr(udcPath, udc)
		return fmt.Errorf("no configs found")
	}
	cfgPath := filepath.Join(cfgDir, configs[0].Name())

	// Link HID function into config
	funcPath := filepath.Join(defaultGadget, "functions", hidFunc)
	symlink := filepath.Join(cfgPath, hidFunc)
	os.Remove(symlink)
	if err := os.Symlink(funcPath, symlink); err != nil {
		writeFileStr(udcPath, udc)
		return fmt.Errorf("symlink HID into config: %w", err)
	}

	// Rebind
	if err := writeFileStr(udcPath, udc); err != nil {
		return fmt.Errorf("rebind UDC: %w", err)
	}

	fmt.Printf("Added FIDO2 HID to existing gadget, bound to %s\n", udc)
	return nil
}

// removeHIDFromGadget removes the HID function from the default gadget.
func removeHIDFromGadget() error {
	defaultGadget := "/config/usb_gadget/g1"
	udcPath := filepath.Join(defaultGadget, "UDC")

	udcData, _ := os.ReadFile(udcPath)
	udc := string(udcData)

	// Unbind
	writeFileStr(udcPath, "")

	// Remove HID symlink from config
	cfgDir := filepath.Join(defaultGadget, "configs")
	configs, _ := os.ReadDir(cfgDir)
	for _, cfg := range configs {
		symlink := filepath.Join(cfgDir, cfg.Name(), hidFunc)
		os.Remove(symlink)
	}

	// Remove HID function
	funcPath := filepath.Join(defaultGadget, "functions", hidFunc)
	os.Remove(funcPath)

	// Rebind
	if len(udc) > 1 {
		writeFileStr(udcPath, udc)
	} else if u, err := findUDC(); err == nil {
		writeFileStr(udcPath, u)
	}

	fmt.Println("Removed FIDO2 HID from gadget")
	return nil
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
	cmd := exec.Command("chmod", "666", dev)
	return cmd.Run()
}
