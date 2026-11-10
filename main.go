package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	defaultStorePath = "/data/local/tmp/fido2-keys.enc"
	version          = "1.5.0"
)

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	switch mode {
	case "serve":
		cmdServe()
	case "setup":
		cmdSetup()
	case "teardown":
		cmdTeardown()
	case "list":
		cmdList()
	case "backup":
		cmdBackup()
	case "version":
		fmt.Println("clave", version)
	case "test-cbor":
		cmdTestCBOR()
	default:
		fmt.Fprintf(os.Stderr, `clave — FIDO2/CTAP2 USB HID authenticator for Android

Usage:
  clave serve   [-password PWD] [-store PATH] [-auto-approve]
                Start FIDO2 daemon (setup gadget + listen)
  clave setup   Set up USB HID gadget only
  clave teardown Remove USB HID gadget
  clave list    [-password PWD] [-store PATH] List credentials
  clave backup  [-password PWD] [-store PATH] -out FILE
  clave version Print version
`)
		os.Exit(1)
	}
}

func cmdServe() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	password := fs.String("password", "", "Master password for key store")
	storePath := fs.String("store", defaultStorePath, "Path to encrypted key store")
	autoApprove := fs.Bool("auto-approve", false, "Auto-approve user presence (INSECURE, for testing)")
	fs.Parse(os.Args[2:])

	if *password == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -password is required")
		os.Exit(1)
	}

	fmt.Println("=== FIDO2 Security Key Daemon ===")
	fmt.Println("Version:", version)

	fmt.Println("\n[1/4] Looking for HID device...")
	hidDev, _ := findHIDDevice()
	if hidDev == "" {
		fmt.Fprintln(os.Stderr, `ERROR: no /dev/hidg* device found.

The clave-hid Magisk module sets up the USB HID gadget at boot.
Install it once, then reboot:

  adb push clave-hid.zip /data/local/tmp/
  adb shell magisk --install-module /data/local/tmp/clave-hid.zip
  adb reboot

After reboot, /dev/hidg* will exist automatically.`)
		os.Exit(1)
	}
	fmt.Printf("\n[2/4] Using HID device: %s\n", hidDev)
	if err := setHIDPermissions(hidDev); err != nil {
		fmt.Printf("Warning: chmod %s: %v\n", hidDev, err)
	}

	// Open key store
	fmt.Println("\n[3/5] Opening key store...")
	store, err := newKeyStore(*storePath, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Key store error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Key store: %s (%d credentials)\n", *storePath, len(store.list()))

	// Load attestation key
	fmt.Println("\n[4/5] Loading attestation key...")
	attestPath := *storePath + ".attest"
	attest, err := loadOrCreateAttestationKey(attestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Attestation key error: %v\n", err)
		os.Exit(1)
	}

	// Set up user presence handler
	fmt.Println("\n[5/5] Starting user presence monitor...")
	presence := newPresenceHandler(*autoApprove)
	if !*autoApprove {
		presence.monitorVolumeKeys()
	}

	// Create CTAP2 handler
	ctap := newCTAP2Handler(store, presence, attest)

	// Open HID device
	hid, err := newCTAPHID(hidDev, ctap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HID open failed: %v\n", err)
		os.Exit(1)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		hid.shutdown()
	}()

	fmt.Println("\n========================================")
	fmt.Println("  FIDO2 Security Key ACTIVE")
	fmt.Println("  Connect USB to computer")
	fmt.Println("  Press Volume Down to approve requests")
	fmt.Println("  Ctrl+C to stop")
	fmt.Println("========================================\n")

	err = hid.serve()
	hid.close()
	if err != nil && !hid.closing.Load() {
		fmt.Fprintf(os.Stderr, "HID serve error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Stopped. HID gadget left active for fast restart.")
}

func cmdSetup() {
	if dev, _ := findHIDDevice(); dev != "" {
		fmt.Printf("HID device already active: %s\n", dev)
		return
	}
	fmt.Println(`No HID device found. Install the clave-hid Magisk module and reboot.
The module sets up USB HID at boot — no runtime gadget changes needed.

  adb push clave-hid.zip /data/local/tmp/
  adb shell magisk --install-module /data/local/tmp/clave-hid.zip
  adb reboot`)
	os.Exit(1)
}

func cmdTeardown() {
	fmt.Println(`To remove FIDO2 HID, disable or remove the Magisk module and reboot:

  rm -rf /data/adb/modules/clave-hid
  reboot`)
}

func cmdList() {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	password := fs.String("password", "", "Master password")
	storePath := fs.String("store", defaultStorePath, "Key store path")
	fs.Parse(os.Args[2:])

	if *password == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -password is required")
		os.Exit(1)
	}

	store, err := newKeyStore(*storePath, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	creds := store.list()
	if len(creds) == 0 {
		fmt.Println("No credentials stored.")
		return
	}

	fmt.Printf("Found %d credential(s):\n\n", len(creds))
	for i, c := range creds {
		fmt.Printf("[%d] RP: %s (%s)\n", i+1, c.RPID, c.RPName)
		fmt.Printf("    User: %s (%s)\n", c.UserName, c.UserDisplay)
		fmt.Printf("    ID:   %x\n", c.CredentialID[:8])
		fmt.Printf("    Signs: %d  Discoverable: %v\n", c.SignCount, c.Discoverable)
		t := time.Unix(c.CreatedAt, 0)
		fmt.Printf("    Created: %s\n\n", t.Format("2006-01-02 15:04:05"))
	}
}

func cmdBackup() {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	password := fs.String("password", "", "Master password")
	storePath := fs.String("store", defaultStorePath, "Key store path")
	outPath := fs.String("out", "", "Output backup file path")
	fs.Parse(os.Args[2:])

	if *password == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -password and -out are required")
		os.Exit(1)
	}

	store, err := newKeyStore(*storePath, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := store.exportBackup(*outPath); err != nil {
		fmt.Fprintf(os.Stderr, "Backup failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Backup saved to %s (%d credentials)\n", *outPath, len(store.list()))
}

func cmdTestCBOR() {
	// Quick self-test for CBOR encoding
	m := map[int]any{
		1: []any{"FIDO_2_0"},
		3: []byte{1, 2, 3, 4},
		4: map[string]any{"rk": true, "up": true},
	}
	data, err := cborEncode(m)
	if err != nil {
		fmt.Println("CBOR encode error:", err)
		os.Exit(1)
	}
	fmt.Printf("Encoded %d bytes: %x\n", len(data), data)

	decoded, err := cborDecode(data)
	if err != nil {
		fmt.Println("CBOR decode error:", err)
		os.Exit(1)
	}
	fmt.Printf("Decoded: %+v\n", decoded)
	fmt.Println("CBOR self-test passed")
}
