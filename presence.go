package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type presenceHandler struct {
	approved  atomic.Bool
	waiting   atomic.Bool
	autoApprove bool
}

func newPresenceHandler(autoApprove bool) *presenceHandler {
	return &presenceHandler{autoApprove: autoApprove}
}

func (p *presenceHandler) isWaiting() bool {
	return p.waiting.Load()
}

// waitForPresence blocks until user confirms presence.
// Returns true if approved, false if timed out (30s).
func (p *presenceHandler) waitForPresence(timeout time.Duration) bool {
	if p.autoApprove {
		fmt.Println("UP: auto-approved")
		return true
	}

	p.approved.Store(false)
	p.waiting.Store(true)
	defer p.waiting.Store(false)

	fmt.Println(">>> PRESS VOLUME DOWN on the phone to approve <<<")

	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			fmt.Println("UP: timed out")
			return false
		case <-ticker.C:
			if p.approved.Load() {
				fmt.Println("UP: approved via button")
				return true
			}
		}
	}
}

// monitorVolumeKeys reads input events from the volume key device.
func (p *presenceHandler) monitorVolumeKeys() {
	devPath := findVolumeKeyDevice()
	if devPath == "" {
		fmt.Println("WARNING: could not find volume key input device, using auto-approve")
		p.autoApprove = true
		return
	}
	fmt.Printf("Monitoring volume keys on %s\n", devPath)

	f, err := os.Open(devPath)
	if err != nil {
		fmt.Printf("WARNING: cannot open %s: %v, using auto-approve\n", devPath, err)
		p.autoApprove = true
		return
	}

	go func() {
		defer f.Close()
		// Linux input_event: struct { time_sec, time_usec uint64; type uint16; code uint16; value int32 }
		// On 64-bit: 24 bytes total
		buf := make([]byte, 24)
		for {
			_, err := f.Read(buf)
			if err != nil {
				return
			}
			evType := binary.LittleEndian.Uint16(buf[16:18])
			evCode := binary.LittleEndian.Uint16(buf[18:20])
			evValue := int32(binary.LittleEndian.Uint32(buf[20:24]))

			// EV_KEY = 1, KEY_VOLUMEDOWN = 114, value 1 = press
			if evType == 1 && evCode == 114 && evValue == 1 {
				if p.waiting.Load() {
					p.approved.Store(true)
				}
			}
		}
	}()
}

func findVolumeKeyDevice() string {
	// Scan /sys/class/input for devices with volume keys
	entries, err := os.ReadDir("/sys/class/input")
	if err != nil {
		return ""
	}

	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "event") {
			continue
		}
		namePath := filepath.Join("/sys/class/input", e.Name(), "device/name")
		data, err := os.ReadFile(namePath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		// MTK volume key device names
		if strings.Contains(strings.ToLower(name), "volume") ||
			strings.Contains(strings.ToLower(name), "gpio-keys") ||
			strings.Contains(strings.ToLower(name), "mtk-kpd") {
			return filepath.Join("/dev/input", e.Name())
		}
	}

	// Fallback: try common paths
	for _, path := range []string{"/dev/input/event0", "/dev/input/event1", "/dev/input/event2"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
