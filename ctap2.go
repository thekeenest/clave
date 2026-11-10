package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

const (
	ctapMakeCredential    = 0x01
	ctapGetAssertion      = 0x02
	ctapGetInfo           = 0x04
	ctapClientPIN         = 0x06
	ctapReset             = 0x07
	ctapGetNextAssertion  = 0x08

	statusOK                = 0x00
	statusInvalidCBOR       = 0x12
	statusInvalidParam      = 0x14
	statusMissingParam      = 0x14
	statusNoCredentials     = 0x2E
	statusNotAllowed        = 0x30
	statusOperationDenied   = 0x27
	statusUPRequired        = 0x2B
	statusKeyStoreFull      = 0x17
	statusUnsupported       = 0x2D
)

// Custom AAGUID for this authenticator (not impersonating any vendor)
var aaguid = [16]byte{
	0x4F, 0x70, 0x65, 0x6E, // "Open"
	0x46, 0x49, 0x44, 0x4F, // "FIDO"
	0x4C, 0x61, 0x6E, 0x63, // "Lanc"
	0x65, 0x6C, 0x6F, 0x74, // "elot"
}

type ctap2Handler struct {
	store    *keyStore
	presence *presenceHandler

	// For getNextAssertion
	pendingAssertions []*credential
	pendingRPIDHash   []byte
	pendingClientData []byte
	pendingFlags      byte
}

func newCTAP2Handler(store *keyStore, presence *presenceHandler) *ctap2Handler {
	return &ctap2Handler{store: store, presence: presence}
}

func (c *ctap2Handler) waitingForPresence() bool {
	return c.presence.isWaiting()
}

func (c *ctap2Handler) handleCommand(cmd byte, data []byte) []byte {
	switch cmd {
	case ctapGetInfo:
		return c.getInfo()
	case ctapMakeCredential:
		return c.makeCredential(data)
	case ctapGetAssertion:
		return c.getAssertion(data)
	case ctapGetNextAssertion:
		return c.getNextAssertion()
	case ctapClientPIN:
		return []byte{statusUnsupported}
	case ctapReset:
		return []byte{statusNotAllowed}
	default:
		return []byte{statusUnsupported}
	}
}

func (c *ctap2Handler) getInfo() []byte {
	info := &CBORMap{}
	// 0x01: versions
	info.Add(int(1), []any{"FIDO_2_0", "FIDO_2_1_PRE"})
	// 0x02: extensions
	info.Add(int(2), []any{"hmac-secret"})
	// 0x03: aaguid
	info.Add(int(3), aaguid[:])
	// 0x04: options
	opts := map[string]any{
		"rk":   true,
		"up":   true,
		"uv":   true,
		"plat": false,
	}
	info.Add(int(4), opts)
	// 0x05: maxMsgSize
	info.Add(int(5), int(2048))
	// 0x06: pinUvAuthProtocols — absent (no PIN, built-in UV only)
	// 0x07: maxCredentialCountInList
	info.Add(int(7), int(8))
	// 0x08: maxCredentialIdLength
	info.Add(int(8), int(128))
	// 0x09: transports
	info.Add(int(9), []any{"usb"})
	// 0x0A: algorithms
	alg := map[string]any{"alg": int(-7), "type": "public-key"}
	info.Add(int(10), []any{alg})
	// 0x0E: firmwareVersion
	info.Add(int(14), int(0x010000))

	encoded, err := cborEncode(info)
	if err != nil {
		fmt.Printf("getInfo CBOR encode error: %v\n", err)
		return []byte{statusInvalidCBOR}
	}
	return append([]byte{statusOK}, encoded...)
}

func (c *ctap2Handler) makeCredential(data []byte) []byte {
	if len(data) == 0 {
		return []byte{statusInvalidCBOR}
	}

	decoded, err := cborDecode(data)
	if err != nil {
		return []byte{statusInvalidCBOR}
	}

	params, ok := decoded.(*CBORMap)
	if !ok {
		return []byte{statusInvalidCBOR}
	}

	// 0x01: clientDataHash (required)
	clientDataHashRaw, ok := cborMapGetInt(params, 1)
	if !ok {
		return []byte{statusMissingParam}
	}
	clientDataHash, ok := clientDataHashRaw.([]byte)
	if !ok || len(clientDataHash) != 32 {
		return []byte{statusInvalidParam}
	}

	// 0x02: rp (required)
	rpRaw, ok := cborMapGetInt(params, 2)
	if !ok {
		return []byte{statusMissingParam}
	}
	rpMap, ok := rpRaw.(*CBORMap)
	if !ok {
		return []byte{statusInvalidParam}
	}
	rpIDRaw, _ := cborMapGetString(rpMap, "id")
	rpID, _ := rpIDRaw.(string)
	rpNameRaw, _ := cborMapGetString(rpMap, "name")
	rpName, _ := rpNameRaw.(string)
	if rpID == "" {
		return []byte{statusInvalidParam}
	}

	// 0x03: user (required)
	userRaw, ok := cborMapGetInt(params, 3)
	if !ok {
		return []byte{statusMissingParam}
	}
	userMap, ok := userRaw.(*CBORMap)
	if !ok {
		return []byte{statusInvalidParam}
	}
	userIDRaw, _ := cborMapGetString(userMap, "id")
	userID, _ := userIDRaw.([]byte)
	userNameRaw, _ := cborMapGetString(userMap, "name")
	userName, _ := userNameRaw.(string)
	userDisplayRaw, _ := cborMapGetString(userMap, "displayName")
	userDisplay, _ := userDisplayRaw.(string)

	// 0x04: pubKeyCredParams (required)
	pubKeyRaw, ok := cborMapGetInt(params, 4)
	if !ok {
		return []byte{statusMissingParam}
	}
	pubKeyList, ok := pubKeyRaw.([]any)
	if !ok {
		return []byte{statusInvalidParam}
	}
	supported := false
	for _, pk := range pubKeyList {
		pkMap, ok := pk.(*CBORMap)
		if !ok {
			continue
		}
		algRaw, _ := cborMapGetString(pkMap, "alg")
		if alg, ok := algRaw.(int); ok && alg == -7 {
			supported = true
			break
		}
	}
	if !supported {
		return []byte{statusUnsupported}
	}

	// 0x05: excludeList (optional) — check for existing credentials
	if exclRaw, ok := cborMapGetInt(params, 5); ok {
		if exclList, ok := exclRaw.([]any); ok {
			for _, item := range exclList {
				if desc, ok := item.(*CBORMap); ok {
					if idRaw, ok := cborMapGetString(desc, "id"); ok {
						if credID, ok := idRaw.([]byte); ok {
							if c.store.findByCredentialID(credID) != nil {
								return []byte{statusNotAllowed}
							}
						}
					}
				}
			}
		}
	}

	// 0x07: options (optional)
	discoverable := false
	if optRaw, ok := cborMapGetInt(params, 7); ok {
		if optMap, ok := optRaw.(*CBORMap); ok {
			if rkRaw, ok := cborMapGetString(optMap, "rk"); ok {
				if rk, ok := rkRaw.(bool); ok {
					discoverable = rk
				}
			}
		}
	}

	// User presence
	fmt.Printf("MakeCredential for RP: %s (user: %s)\n", rpID, userName)
	if !c.presence.waitForPresence(30 * 1000000000) { // 30s in ns
		return []byte{statusOperationDenied}
	}

	// Generate credential
	cred, err := c.store.createCredential(rpID, rpName, userID, userName, userDisplay, discoverable)
	if err != nil {
		fmt.Printf("Error creating credential: %v\n", err)
		return []byte{statusKeyStoreFull}
	}

	// Build authenticator data
	authData := buildAuthData(rpID, cred, true)

	// Build attestation signature over authData + clientDataHash
	signData := append(authData, clientDataHash...)
	sigHash := sha256.Sum256(signData)
	r, s, err := ecdsa.Sign(rand.Reader, cred.ecdsaKey(), sigHash[:])
	if err != nil {
		return []byte{statusInvalidCBOR}
	}
	sig := marshalDERSignature(r, s)

	// Build attestation statement (string keys per CTAP2 packed format)
	attStmt := &CBORMap{}
	attStmt.Add("alg", int(-7))
	attStmt.Add("sig", sig)

	// CTAP2 response uses integer keys: 0x01=fmt, 0x02=authData, 0x03=attStmt
	attObj := &CBORMap{}
	attObj.Add(int(1), "packed")
	attObj.Add(int(2), authData)
	attObj.Add(int(3), attStmt)

	encoded, err := cborEncode(attObj)
	if err != nil {
		return []byte{statusInvalidCBOR}
	}

	fmt.Printf("Credential created: %x (RP: %s)\n", cred.CredentialID[:8], rpID)
	return append([]byte{statusOK}, encoded...)
}

func (c *ctap2Handler) getAssertion(data []byte) []byte {
	if len(data) == 0 {
		return []byte{statusInvalidCBOR}
	}

	decoded, err := cborDecode(data)
	if err != nil {
		return []byte{statusInvalidCBOR}
	}

	params, ok := decoded.(*CBORMap)
	if !ok {
		return []byte{statusInvalidCBOR}
	}

	// 0x01: rpId (required)
	rpIDRaw, ok := cborMapGetInt(params, 1)
	if !ok {
		return []byte{statusMissingParam}
	}
	rpID, ok := rpIDRaw.(string)
	if !ok {
		return []byte{statusInvalidParam}
	}

	// 0x02: clientDataHash (required)
	clientDataHashRaw, ok := cborMapGetInt(params, 2)
	if !ok {
		return []byte{statusMissingParam}
	}
	clientDataHash, ok := clientDataHashRaw.([]byte)
	if !ok || len(clientDataHash) != 32 {
		return []byte{statusInvalidParam}
	}

	// 0x03: allowList (optional)
	var candidates []*credential
	if allowRaw, ok := cborMapGetInt(params, 3); ok {
		if allowList, ok := allowRaw.([]any); ok {
			for _, item := range allowList {
				if desc, ok := item.(*CBORMap); ok {
					if idRaw, ok := cborMapGetString(desc, "id"); ok {
						if credID, ok := idRaw.([]byte); ok {
							if cred := c.store.findByCredentialID(credID); cred != nil && cred.RPID == rpID {
								candidates = append(candidates, cred)
							}
						}
					}
				}
			}
		}
	}

	// If no allowList, search discoverable credentials
	if candidates == nil {
		candidates = c.store.findDiscoverableByRPID(rpID)
	}

	if len(candidates) == 0 {
		return []byte{statusNoCredentials}
	}

	// User presence
	fmt.Printf("GetAssertion for RP: %s (%d candidate(s))\n", rpID, len(candidates))
	if !c.presence.waitForPresence(30 * 1000000000) {
		return []byte{statusOperationDenied}
	}

	// Store remaining for getNextAssertion
	c.pendingAssertions = candidates[1:]
	c.pendingRPIDHash = rpIDHash(rpID)
	c.pendingClientData = clientDataHash

	return c.buildAssertionResponse(candidates[0], rpID, clientDataHash, len(candidates))
}

func (c *ctap2Handler) getNextAssertion() []byte {
	if len(c.pendingAssertions) == 0 {
		return []byte{statusNotAllowed}
	}

	cred := c.pendingAssertions[0]
	c.pendingAssertions = c.pendingAssertions[1:]

	return c.buildAssertionResponse(cred, cred.RPID, c.pendingClientData, 0)
}

func (c *ctap2Handler) buildAssertionResponse(cred *credential, rpID string, clientDataHash []byte, totalCreds int) []byte {
	// Increment counter
	count := c.store.incrementCounter(cred.CredentialID)

	// Flags: UP (0x01) + UV (0x04)
	flags := byte(0x01 | 0x04)

	// Build authData (no attested credential data for assertion)
	rpHash := rpIDHash(rpID)
	authData := make([]byte, 37)
	copy(authData[0:32], rpHash)
	authData[32] = flags
	binary.BigEndian.PutUint32(authData[33:37], count)

	// Sign
	signData := append(authData, clientDataHash...)
	sigHash := sha256.Sum256(signData)
	r, s, err := ecdsa.Sign(rand.Reader, cred.ecdsaKey(), sigHash[:])
	if err != nil {
		return []byte{statusInvalidCBOR}
	}
	sig := marshalDERSignature(r, s)

	resp := &CBORMap{}
	// 0x01: credential descriptor
	credDesc := map[string]any{
		"id":   cred.CredentialID,
		"type": "public-key",
	}
	resp.Add(int(1), credDesc)
	// 0x02: authData
	resp.Add(int(2), authData)
	// 0x03: signature
	resp.Add(int(3), sig)
	// 0x04: user (for discoverable credentials)
	if cred.Discoverable {
		user := map[string]any{"id": cred.UserID}
		if cred.UserName != "" {
			user["name"] = cred.UserName
		}
		if cred.UserDisplay != "" {
			user["displayName"] = cred.UserDisplay
		}
		resp.Add(int(4), user)
	}
	// 0x05: numberOfCredentials
	if totalCreds > 1 {
		resp.Add(int(5), totalCreds)
	}

	encoded, err := cborEncode(resp)
	if err != nil {
		return []byte{statusInvalidCBOR}
	}

	fmt.Printf("Assertion signed for RP: %s (counter: %d)\n", rpID, count)
	return append([]byte{statusOK}, encoded...)
}

func buildAuthData(rpID string, cred *credential, includeAttestedCred bool) []byte {
	rpHash := rpIDHash(rpID)

	flags := byte(0x01 | 0x04) // UP + UV
	if includeAttestedCred {
		flags |= 0x40 // AT
	}

	authData := make([]byte, 37)
	copy(authData[0:32], rpHash)
	authData[32] = flags
	binary.BigEndian.PutUint32(authData[33:37], cred.SignCount)

	if includeAttestedCred {
		// AAGUID (16 bytes)
		authData = append(authData, aaguid[:]...)
		// Credential ID length (2 bytes big-endian)
		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(cred.CredentialID)))
		authData = append(authData, credIDLen...)
		// Credential ID
		authData = append(authData, cred.CredentialID...)
		// COSE public key
		pubKey := coseEncodeES256PubKey(cred.ecdsaKey().PublicKey)
		authData = append(authData, pubKey...)
	}

	return authData
}

func rpIDHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

func coseEncodeES256PubKey(pub ecdsa.PublicKey) []byte {
	m := &CBORMap{}
	m.Add(int(1), int(2))    // kty: EC2
	m.Add(int(3), int(-7))   // alg: ES256
	m.Add(int(-1), int(1))   // crv: P-256
	m.Add(int(-2), padTo32(pub.X.Bytes())) // x
	m.Add(int(-3), padTo32(pub.Y.Bytes())) // y
	encoded, _ := cborEncode(m)
	return encoded
}

func marshalDERSignature(r, s *big.Int) []byte {
	rb := r.Bytes()
	sb := s.Bytes()

	// Ensure S is in low-S form (required by FIDO2)
	halfOrder := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(elliptic.P256().Params().N, s)
		sb = s.Bytes()
	}

	// DER encoding
	if len(rb) > 0 && rb[0]&0x80 != 0 {
		rb = append([]byte{0}, rb...)
	}
	if len(sb) > 0 && sb[0]&0x80 != 0 {
		sb = append([]byte{0}, sb...)
	}

	der := make([]byte, 0, 6+len(rb)+len(sb))
	der = append(der, 0x30, byte(4+len(rb)+len(sb)))
	der = append(der, 0x02, byte(len(rb)))
	der = append(der, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)
	return der
}
