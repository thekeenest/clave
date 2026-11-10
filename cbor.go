package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

var errCBOR = errors.New("cbor: invalid data")

func cborEncodeUint(major byte, n uint64) []byte {
	major <<= 5
	switch {
	case n <= 23:
		return []byte{major | byte(n)}
	case n <= 0xFF:
		return []byte{major | 24, byte(n)}
	case n <= 0xFFFF:
		b := make([]byte, 3)
		b[0] = major | 25
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xFFFFFFFF:
		b := make([]byte, 5)
		b[0] = major | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = major | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}

func cborEncodeInt(v int64) []byte {
	if v >= 0 {
		return cborEncodeUint(0, uint64(v))
	}
	return cborEncodeUint(1, uint64(-1-v))
}

func cborEncodeBytes(b []byte) []byte {
	hdr := cborEncodeUint(2, uint64(len(b)))
	return append(hdr, b...)
}

func cborEncodeString(s string) []byte {
	hdr := cborEncodeUint(3, uint64(len(s)))
	return append(hdr, []byte(s)...)
}

func cborEncodeBool(v bool) []byte {
	if v {
		return []byte{0xf5}
	}
	return []byte{0xf4}
}

func cborEncodeNil() []byte {
	return []byte{0xf6}
}

func cborEncodeArrayHeader(n int) []byte {
	return cborEncodeUint(4, uint64(n))
}

func cborEncodeMapHeader(n int) []byte {
	return cborEncodeUint(5, uint64(n))
}

// cborEncode encodes a Go value to CBOR.
// Supported types: int, int64, uint64, []byte, string, bool, nil,
// []any, map[int]any, map[string]any, CBORMap
func cborEncode(v any) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return cborEncodeNil(), nil
	case bool:
		return cborEncodeBool(val), nil
	case int:
		return cborEncodeInt(int64(val)), nil
	case int64:
		return cborEncodeInt(val), nil
	case uint64:
		return cborEncodeUint(0, val), nil
	case []byte:
		return cborEncodeBytes(val), nil
	case string:
		return cborEncodeString(val), nil
	case []any:
		out := cborEncodeArrayHeader(len(val))
		for _, item := range val {
			enc, err := cborEncode(item)
			if err != nil {
				return nil, err
			}
			out = append(out, enc...)
		}
		return out, nil
	case CBORMap:
		return val.Encode()
	case *CBORMap:
		return val.Encode()
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		out := cborEncodeMapHeader(len(val))
		for _, k := range keys {
			out = append(out, cborEncodeString(k)...)
			enc, err := cborEncode(val[k])
			if err != nil {
				return nil, err
			}
			out = append(out, enc...)
		}
		return out, nil
	case map[int]any:
		keys := make([]int, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			ei := cborEncodeInt(int64(keys[i]))
			ej := cborEncodeInt(int64(keys[j]))
			if len(ei) != len(ej) {
				return len(ei) < len(ej)
			}
			for x := 0; x < len(ei); x++ {
				if ei[x] != ej[x] {
					return ei[x] < ej[x]
				}
			}
			return false
		})
		out := cborEncodeMapHeader(len(val))
		for _, k := range keys {
			out = append(out, cborEncodeInt(int64(k))...)
			enc, err := cborEncode(val[k])
			if err != nil {
				return nil, err
			}
			out = append(out, enc...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cbor: unsupported type %T", v)
	}
}

// CBORMap preserves insertion order for mixed-key maps.
type CBORMap struct {
	Keys   []any
	Values []any
}

func (m *CBORMap) Add(k, v any) {
	m.Keys = append(m.Keys, k)
	m.Values = append(m.Values, v)
}

func (m *CBORMap) Encode() ([]byte, error) {
	out := cborEncodeMapHeader(len(m.Keys))
	for i, k := range m.Keys {
		kenc, err := cborEncode(k)
		if err != nil {
			return nil, err
		}
		venc, err := cborEncode(m.Values[i])
		if err != nil {
			return nil, err
		}
		out = append(out, kenc...)
		out = append(out, venc...)
	}
	return out, nil
}

// --- Decoder ---

type cborDecoder struct {
	data []byte
	pos  int
}

func (d *cborDecoder) remaining() int { return len(d.data) - d.pos }

func (d *cborDecoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, errCBOR
	}
	b := d.data[d.pos]
	d.pos++
	return b, nil
}

func (d *cborDecoder) readN(n int) ([]byte, error) {
	if d.pos+n > len(d.data) {
		return nil, errCBOR
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

func (d *cborDecoder) readArg(info byte) (uint64, error) {
	switch {
	case info <= 23:
		return uint64(info), nil
	case info == 24:
		b, err := d.readByte()
		return uint64(b), err
	case info == 25:
		bs, err := d.readN(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(bs)), nil
	case info == 26:
		bs, err := d.readN(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(bs)), nil
	case info == 27:
		bs, err := d.readN(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(bs), nil
	}
	return 0, errCBOR
}

func (d *cborDecoder) decode() (any, error) {
	b, err := d.readByte()
	if err != nil {
		return nil, err
	}
	major := b >> 5
	info := b & 0x1f

	switch major {
	case 0: // unsigned int
		n, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		if n <= math.MaxInt64 {
			return int(n), nil
		}
		return n, nil
	case 1: // negative int
		n, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		return int(-1 - int64(n)), nil
	case 2: // byte string
		n, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		return d.readN(int(n))
	case 3: // text string
		n, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		bs, err := d.readN(int(n))
		if err != nil {
			return nil, err
		}
		return string(bs), nil
	case 4: // array
		n, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		arr := make([]any, int(n))
		for i := range arr {
			arr[i], err = d.decode()
			if err != nil {
				return nil, err
			}
		}
		return arr, nil
	case 5: // map
		n, err := d.readArg(info)
		if err != nil {
			return nil, err
		}
		m := &CBORMap{}
		for i := 0; i < int(n); i++ {
			k, err := d.decode()
			if err != nil {
				return nil, err
			}
			v, err := d.decode()
			if err != nil {
				return nil, err
			}
			m.Add(k, v)
		}
		return m, nil
	case 7: // simple values
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, fmt.Errorf("cbor: unsupported simple value %d", info)
	}
	return nil, fmt.Errorf("cbor: unsupported major type %d", major)
}

func cborDecode(data []byte) (any, error) {
	d := &cborDecoder{data: data}
	return d.decode()
}

func cborMapGet(m *CBORMap, key any) (any, bool) {
	for i, k := range m.Keys {
		if fmt.Sprintf("%v", k) == fmt.Sprintf("%v", key) {
			return m.Values[i], true
		}
	}
	return nil, false
}

func cborMapGetInt(m *CBORMap, key int) (any, bool) {
	for i, k := range m.Keys {
		switch kv := k.(type) {
		case int:
			if kv == key {
				return m.Values[i], true
			}
		}
	}
	return nil, false
}

func cborMapGetString(m *CBORMap, key string) (any, bool) {
	for i, k := range m.Keys {
		switch kv := k.(type) {
		case string:
			if kv == key {
				return m.Values[i], true
			}
		}
	}
	return nil, false
}
