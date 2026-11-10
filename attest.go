package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
)

type attestationKey struct {
	key  *ecdsa.PrivateKey
	cert []byte // DER-encoded X.509 certificate
}

func loadOrCreateAttestationKey(path string) (*attestationKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		ak := &attestationKey{}
		if err := ak.unmarshal(data); err == nil {
			fmt.Printf("Attestation key loaded from %s\n", path)
			return ak, nil
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate attestation key: %w", err)
	}

	cert, err := createAttestationCert(key)
	if err != nil {
		return nil, err
	}

	ak := &attestationKey{key: key, cert: cert}
	data, err := ak.marshal()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("save attestation key: %w", err)
	}
	fmt.Printf("Attestation key generated and saved to %s\n", path)
	return ak, nil
}

func createAttestationCert(key *ecdsa.PrivateKey) ([]byte, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// FIDO AAGUID extension OID: 1.3.6.1.4.1.45724.1.1.4
	aaguidOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	// The AAGUID is wrapped in an OCTET STRING inside the extension value
	aaguidASN1, _ := asn1.Marshal(aaguid[:])

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "Clave FIDO2 Attestation",
			Organization:       []string{"Clave"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			Country:            []string{"US"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       aaguidOID,
				Critical: false,
				Value:    aaguidASN1,
			},
		},
	}

	return x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
}

// sign creates a DER-encoded ECDSA signature over sha256(data) using the attestation key.
func (ak *attestationKey) sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, ak.key, h[:])
	if err != nil {
		return nil, err
	}
	return marshalDERSignature(r, s), nil
}

type attestKeyJSON struct {
	D    []byte `json:"d"`
	X    []byte `json:"x"`
	Y    []byte `json:"y"`
	Cert []byte `json:"cert"`
}

func (ak *attestationKey) marshal() ([]byte, error) {
	return json.Marshal(&attestKeyJSON{
		D:    padTo32(ak.key.D.Bytes()),
		X:    padTo32(ak.key.PublicKey.X.Bytes()),
		Y:    padTo32(ak.key.PublicKey.Y.Bytes()),
		Cert: ak.cert,
	})
}

func (ak *attestationKey) unmarshal(data []byte) error {
	var j attestKeyJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	ak.key = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(j.X),
			Y:     new(big.Int).SetBytes(j.Y),
		},
		D: new(big.Int).SetBytes(j.D),
	}
	ak.cert = j.Cert
	return nil
}
