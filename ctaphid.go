package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	hidReportSize = 64

	cmdInit      = 0x06 | 0x80
	cmdPing      = 0x01 | 0x80
	cmdMsg       = 0x03 | 0x80
	cmdCBOR      = 0x10 | 0x80
	cmdCancel    = 0x11 | 0x80
	cmdError     = 0x3F | 0x80
	cmdKeepalive = 0x3B | 0x80
	cmdWink      = 0x08 | 0x80
	cmdLock      = 0x04 | 0x80

	errInvalidCmd  = 0x01
	errInvalidPar  = 0x02
	errInvalidLen  = 0x03
	errInvalidSeq  = 0x04
	errMsgTimeout  = 0x05
	errChannelBusy = 0x06
	errOther       = 0x7F

	capWink = 0x01
	capCBOR = 0x04
	capNMSG = 0x08

	broadcastCID = 0xFFFFFFFF
)

type ctapHID struct {
	fd       int
	name     string
	ctap     *ctap2Handler
	mu       sync.Mutex
	channels map[uint32]time.Time
	nextCID  uint32
	done     chan struct{}
	closing  atomic.Bool
}

func newCTAPHID(devPath string, ctap *ctap2Handler) (*ctapHID, error) {
	fd, err := syscall.Open(devPath, syscall.O_RDWR|syscall.O_NONBLOCK, 0666)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", devPath, err)
	}
	return &ctapHID{
		fd:       fd,
		name:     devPath,
		ctap:     ctap,
		channels: make(map[uint32]time.Time),
		nextCID:  1,
		done:     make(chan struct{}),
	}, nil
}

func (h *ctapHID) shutdown() {
	if h.closing.CompareAndSwap(false, true) {
		close(h.done)
	}
}

func (h *ctapHID) close() {
	syscall.Close(h.fd)
}

func (h *ctapHID) readPacket() ([]byte, error) {
	buf := make([]byte, hidReportSize)
	offset := 0
	for offset < hidReportSize {
		select {
		case <-h.done:
			return nil, fmt.Errorf("shutdown")
		default:
		}

		n, err := syscall.Read(h.fd, buf[offset:])
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if err == syscall.EINTR {
				continue
			}
			return nil, fmt.Errorf("read fd: %w", err)
		}
		if n > 0 {
			offset += n
		}
	}
	return buf, nil
}

func (h *ctapHID) writePacket(data []byte) error {
	if len(data) < hidReportSize {
		padded := make([]byte, hidReportSize)
		copy(padded, data)
		data = padded
	}
	_, err := syscall.Write(h.fd, data[:hidReportSize])
	return err
}

func (h *ctapHID) sendResponse(cid uint32, cmd byte, payload []byte) error {
	total := len(payload)
	fmt.Printf("TX: CID=%08X CMD=%02X LEN=%d [%x]\n", cid, cmd, total, payload[:min(16, len(payload))])

	pkt := make([]byte, hidReportSize)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmd
	binary.BigEndian.PutUint16(pkt[5:7], uint16(total))

	dataLen := min(total, hidReportSize-7)
	copy(pkt[7:], payload[:dataLen])
	if err := h.writePacket(pkt); err != nil {
		fmt.Printf("TX pkt 0 write error: %v\n", err)
		return err
	}

	sent := dataLen
	seq := byte(0)
	for sent < total {
		time.Sleep(2 * time.Millisecond)
		pkt = make([]byte, hidReportSize)
		binary.BigEndian.PutUint32(pkt[0:4], cid)
		pkt[4] = seq
		seq++

		dataLen = min(total-sent, hidReportSize-5)
		copy(pkt[5:], payload[sent:sent+dataLen])
		if err := h.writePacket(pkt); err != nil {
			fmt.Printf("TX pkt %d write error: %v\n", seq, err)
			return err
		}
		sent += dataLen
	}
	fmt.Printf("TX: sent %d packets\n", int(seq)+1)
	return nil
}

func (h *ctapHID) sendError(cid uint32, code byte) error {
	return h.sendResponse(cid, cmdError, []byte{code})
}

func (h *ctapHID) sendKeepalive(cid uint32, status byte) error {
	return h.sendResponse(cid, cmdKeepalive, []byte{status})
}

func (h *ctapHID) allocCID() uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	cid := h.nextCID
	h.nextCID++
	if h.nextCID == 0 || h.nextCID == broadcastCID {
		h.nextCID = 1
	}
	h.channels[cid] = time.Now()
	return cid
}

func (h *ctapHID) serve() error {
	fmt.Println("CTAPHID: listening on", h.name)
	for {
		pkt, err := h.readPacket()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		cid := binary.BigEndian.Uint32(pkt[0:4])
		cmdByte := pkt[4]

		fmt.Printf("RX: CID=%08X CMD=%02X [%x...]\n", cid, cmdByte, pkt[:min(16, len(pkt))])

		// Initialization packet (bit 7 set)
		if cmdByte&0x80 == 0 {
			fmt.Printf("  continuation packet (seq=%d), ignoring (no active msg)\n", cmdByte)
			continue
		}

		bcnt := int(binary.BigEndian.Uint16(pkt[5:7]))
		payload := make([]byte, 0, bcnt)

		// Copy init data
		initData := min(bcnt, hidReportSize-7)
		payload = append(payload, pkt[7:7+initData]...)

		// Read continuation packets
		expectedSeq := byte(0)
		for len(payload) < bcnt {
			cpkt, err := h.readPacket()
			if err != nil {
				return err
			}
			ccid := binary.BigEndian.Uint32(cpkt[0:4])
			if ccid != cid {
				h.sendError(ccid, errChannelBusy)
				continue
			}
			if cpkt[4] != expectedSeq {
				h.sendError(cid, errInvalidSeq)
				break
			}
			expectedSeq++

			contData := min(bcnt-len(payload), hidReportSize-5)
			payload = append(payload, cpkt[5:5+contData]...)
		}

		if len(payload) < bcnt {
			continue
		}

		h.handleCommand(cid, cmdByte, payload)
	}
}

func (h *ctapHID) handleCommand(cid uint32, cmd byte, payload []byte) {
	switch cmd {
	case cmdInit:
		h.handleInit(cid, payload)
	case cmdPing:
		h.sendResponse(cid, cmdPing, payload)
	case cmdCBOR:
		h.handleCBOR(cid, payload)
	case cmdCancel:
		// Nothing to cancel in our simple implementation
	case cmdWink:
		fmt.Println("WINK!")
		h.sendResponse(cid, cmdWink, nil)
	case cmdMsg:
		// U2F message — respond with error (we only do CTAP2)
		h.sendError(cid, errInvalidCmd)
	default:
		h.sendError(cid, errInvalidCmd)
	}
}

func (h *ctapHID) handleInit(cid uint32, payload []byte) {
	if len(payload) != 8 {
		h.sendError(cid, errInvalidLen)
		return
	}

	newCID := h.allocCID()
	resp := make([]byte, 17)
	copy(resp[0:8], payload) // nonce
	binary.BigEndian.PutUint32(resp[8:12], newCID)
	resp[12] = 2 // CTAPHID protocol version
	resp[13] = 1 // Major version
	resp[14] = 0 // Minor version
	resp[15] = 0 // Build version
	resp[16] = capCBOR | capWink | capNMSG

	h.sendResponse(cid, cmdInit, resp)
	fmt.Printf("INIT: allocated CID 0x%08X\n", newCID)
}

func (h *ctapHID) handleCBOR(cid uint32, payload []byte) {
	if len(payload) < 1 {
		h.sendError(cid, errInvalidLen)
		return
	}

	ctapCmd := payload[0]
	ctapData := payload[1:]

	needsUP := ctapCmd == ctapMakeCredential || ctapCmd == ctapGetAssertion

	done := make(chan []byte, 1)
	go func() {
		resp := h.ctap.handleCommand(ctapCmd, ctapData)
		done <- resp
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	keepalivesSent := 0
	var bufferedResp []byte

	for {
		select {
		case resp := <-done:
			if needsUP && keepalivesSent < 3 {
				bufferedResp = resp
				h.sendKeepalive(cid, 2)
				keepalivesSent++
				continue
			}
			if err := h.sendResponse(cid, cmdCBOR, resp); err != nil {
				fmt.Printf("TX error: %v\n", err)
			}
			return
		case <-ticker.C:
			h.sendKeepalive(cid, 2)
			keepalivesSent++
			if bufferedResp != nil && keepalivesSent >= 3 {
				if err := h.sendResponse(cid, cmdCBOR, bufferedResp); err != nil {
					fmt.Printf("TX error: %v\n", err)
				}
				return
			}
		}
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
