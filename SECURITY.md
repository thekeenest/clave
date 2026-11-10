# Security

## Reporting vulnerabilities

If you find a security issue, email **loveledger13@gmail.com** with the subject "clave security." Do not open a public issue. I'll respond within 48 hours.

## Threat model

Clave is a software FIDO2 authenticator. It is **not** equivalent to a hardware security key with a secure element.

**What it protects against:**
- Phishing — WebAuthn/FIDO2 protocol binds credentials to origin, so phished URLs get no valid signature
- Password reuse — credentials are per-site ECDSA key pairs
- Remote key theft — the encrypted key file is unreadable without the password
- Unauthorized signing — every operation requires a physical button press on the device

**What it does NOT protect against:**
- A rooted attacker on the running phone can read memory and extract key material
- Physical access to the device + knowledge of the password = full key access
- The phone has no tamper detection, anti-glitching, or side-channel hardening
- Lost device + no backup = permanent credential loss

## Cryptography

| Primitive | Usage |
|---|---|
| ECDSA P-256 (ES256) | Per-credential signing keys |
| AES-256-GCM | Key store encryption at rest |
| PBKDF2-HMAC-SHA256 | Password → encryption key (100,000 iterations) |
| SHA-256 | RP ID hashing, signature input |

DER-encoded signatures use low-S normalization per SEC1 and FIDO2 requirements.

## Key storage

Credentials are stored as a JSON array, encrypted with AES-256-GCM. The encryption key is derived from the user's password with PBKDF2. The encrypted file lives at a user-specified path (default: `/data/local/tmp/fido2-keys.enc`).

A random 12-byte GCM nonce is generated per save. The nonce is prepended to the ciphertext.

## Not FIDO certified

Clave is not certified by the FIDO Alliance. Sites or organizations that require FIDO certification will reject it. The AAGUID (`4F70656E4649444F4C616E63656C6F74`) is unique to this project and does not impersonate any certified vendor.
