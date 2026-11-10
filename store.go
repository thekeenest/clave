package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

type credential struct {
	CredentialID []byte `json:"credential_id"`
	PrivKeyD     []byte `json:"privkey_d"`
	PrivKeyX     []byte `json:"privkey_x"`
	PrivKeyY     []byte `json:"privkey_y"`
	RPID         string `json:"rp_id"`
	RPName       string `json:"rp_name"`
	UserID       []byte `json:"user_id"`
	UserName     string `json:"user_name"`
	UserDisplay  string `json:"user_display"`
	SignCount    uint32 `json:"sign_count"`
	CreatedAt    int64  `json:"created_at"`
	Discoverable bool   `json:"discoverable"`
}

func (c *credential) ecdsaKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(c.PrivKeyX),
			Y:     new(big.Int).SetBytes(c.PrivKeyY),
		},
		D: new(big.Int).SetBytes(c.PrivKeyD),
	}
}

type keyStore struct {
	mu          sync.RWMutex
	credentials []*credential
	filePath    string
	masterKey   []byte
}

func newKeyStore(path string, password string) (*keyStore, error) {
	key := deriveKey(password, []byte("fido2-key-lancelot-salt-v1"))
	ks := &keyStore{
		filePath:  path,
		masterKey: key,
	}
	if err := ks.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return ks, nil
}

// PBKDF2-HMAC-SHA256
func deriveKey(password string, salt []byte) []byte {
	iterations := 100000
	dkLen := 32

	prf := func(key, data []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(data)
		return h.Sum(nil)
	}

	pwd := []byte(password)
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	block[len(salt)] = 0
	block[len(salt)+1] = 0
	block[len(salt)+2] = 0
	block[len(salt)+3] = 1

	u := prf(pwd, block)
	dk := make([]byte, dkLen)
	copy(dk, u)

	for i := 1; i < iterations; i++ {
		u = prf(pwd, u)
		for j := range dk {
			dk[j] ^= u[j]
		}
	}
	return dk
}

func (ks *keyStore) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ks.masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, data, nil), nil
}

func (ks *keyStore) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ks.masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, data[:ns], data[ns:], nil)
}

func (ks *keyStore) save() error {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.saveLocked()
}

func (ks *keyStore) saveLocked() error {
	jsonData, err := json.Marshal(ks.credentials)
	if err != nil {
		return err
	}
	enc, err := ks.encrypt(jsonData)
	if err != nil {
		return err
	}
	return os.WriteFile(ks.filePath, enc, 0600)
}

func (ks *keyStore) load() error {
	data, err := os.ReadFile(ks.filePath)
	if err != nil {
		return err
	}
	dec, err := ks.decrypt(data)
	if err != nil {
		return fmt.Errorf("decrypt keystore (wrong password?): %w", err)
	}
	return json.Unmarshal(dec, &ks.credentials)
}

func (ks *keyStore) createCredential(rpID, rpName string, userID []byte, userName, userDisplay string, discoverable bool) (*credential, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	credID := make([]byte, 32)
	rand.Read(credID)

	cred := &credential{
		CredentialID: credID,
		PrivKeyD:     key.D.Bytes(),
		PrivKeyX:     key.PublicKey.X.Bytes(),
		PrivKeyY:     key.PublicKey.Y.Bytes(),
		RPID:         rpID,
		RPName:       rpName,
		UserID:       userID,
		UserName:     userName,
		UserDisplay:  userDisplay,
		SignCount:    0,
		CreatedAt:    time.Now().Unix(),
		Discoverable: discoverable,
	}

	// Pad key coordinates to 32 bytes
	cred.PrivKeyD = padTo32(cred.PrivKeyD)
	cred.PrivKeyX = padTo32(cred.PrivKeyX)
	cred.PrivKeyY = padTo32(cred.PrivKeyY)

	ks.mu.Lock()
	ks.credentials = append(ks.credentials, cred)
	ks.mu.Unlock()

	if err := ks.save(); err != nil {
		return nil, err
	}
	return cred, nil
}

func (ks *keyStore) findByCredentialID(credID []byte) *credential {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for _, c := range ks.credentials {
		if bytesEqual(c.CredentialID, credID) {
			return c
		}
	}
	return nil
}

func (ks *keyStore) findByRPID(rpID string) []*credential {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var results []*credential
	for _, c := range ks.credentials {
		if c.RPID == rpID {
			results = append(results, c)
		}
	}
	return results
}

func (ks *keyStore) findDiscoverableByRPID(rpID string) []*credential {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var results []*credential
	for _, c := range ks.credentials {
		if c.RPID == rpID && c.Discoverable {
			results = append(results, c)
		}
	}
	return results
}

func (ks *keyStore) incrementCounter(credID []byte) uint32 {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, c := range ks.credentials {
		if bytesEqual(c.CredentialID, credID) {
			c.SignCount++
			ks.saveLocked()
			return c.SignCount
		}
	}
	return 0
}

func (ks *keyStore) list() []*credential {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]*credential, len(ks.credentials))
	copy(out, ks.credentials)
	return out
}

func (ks *keyStore) exportBackup(path string) error {
	data, err := os.ReadFile(ks.filePath)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
