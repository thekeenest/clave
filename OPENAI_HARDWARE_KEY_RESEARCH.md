# OpenAI Advanced Account Security / Daybreak hardware-key classification — research log

Status as of 2026-11-10, clave v1.6.1. This document is the full findings record for
why clave (a self-built FIDO2/CTAP2 authenticator) registers successfully with
OpenAI but is never classified as a "non-exportable hardware key," which blocks
the Continue button on `auth.openai.com/advanced-account-security/secure-methods`.

## TL;DR

OpenAI's backend computes a specific boolean per credential, `is_non_exportable_hardware_key`,
independently of a looser `is_security_key` boolean and of the cosmetic authenticator
model-name label. Flipping it almost certainly requires the attestation certificate
chain (x5c) to validate against a trust root OpenAI recognizes — in all observed
evidence, that means a genuine Yubico-manufactured key, because even other
FIDO2-certified hardware vendors (TrustKey T110/T120) are explicitly excluded. A
self-signed certificate, regardless of claimed AAGUID/model, cannot produce a chain
that validates against Yubico's real CA, because that CA's private key lives in
non-exportable secure hardware we do not possess. No protocol-level field, extension,
or AAGUID spoof changes this. This was the working conclusion after exhausting every
non-destructive technical avenue; see "What's left to try" at the end for the only
remaining non-cryptographic angles, all low-probability.

## Hard evidence collected (not inference)

### 1. The real backend response — `/passkeys` list endpoint

Captured directly from Chrome DevTools Network tab (user-authenticated session),
response body for `GET` (or similar) passkeys listing on
`auth.openai.com`/`chatgpt.com` (routed through `https://chatgpt.com/ces/v1/...`
and `auth.openai.com` endpoints):

```json
{
  "passkeys": [
    {
      "factor_id": "6af36aad99e88191bdffb5b4dc0deb10",
      "credential_id": "bl-C-4n0776DiUVP03YqU3b5jXL5unB5i9RnUYeKNTw",
      "authenticator_name": "YubiKey 5 Series with NFC",
      "created_at": 1794337453,
      "is_non_device_bound": true,
      "is_security_key": true,
      "is_non_exportable_hardware_key": false
    },
    {
      "...": "Google Password Manager / Apple Passwords entries, all is_security_key:false"
    }
  ]
}
```

This is the single most important fact collected in this investigation:

- `authenticator_name: "YubiKey 5 Series with NFC"` — this is a **cosmetic label**,
  driven purely by AAGUID lookup. It flips instantly the moment clave's AAGUID
  constant changes, with zero relationship to whether the attestation is valid.
- `is_security_key: true` — clave's credential satisfies this. Likely driven by
  authenticator attachment == cross-platform, transports, and/or presence of a
  (non-"none") attestation statement. This flag is **not** the Continue gate.
- `is_non_exportable_hardware_key: false` — **this is the actual Continue gate.**
  It stayed `false` across every variant clave produced: custom AAGUID + x5c,
  YubiKey AAGUID + `fmt:"none"`, YubiKey AAGUID + x5c, YubiKey AAGUID + x5c +
  credProtect/hmac-secret extension compliance. Nothing moved this bit.

### 2. The real registration request — `start.json` (passkey_creation_options)

Captured from the actual `POST` that starts a WebAuthn ceremony:

```json
{
  "passkey_creation_options": {
    "rp": { "name": "OpenAI", "id": "openai.com" },
    "user": { "name": "...", "id": "...", "displayName": "..." },
    "challenge": "...",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "excludeCredentials": [ ... ],
    "authenticatorSelection": {
      "requireResidentKey": true,
      "userVerification": "required",
      "residentKey": "required"
    },
    "attestation": "direct",
    "extensions": {
      "credProps": true,
      "prf": { "eval": { "first": "..." } }
    },
    "timeout": 600000
  },
  "mfa_request_id": "..."
}
```

Key fact: **`"attestation": "direct"`** is explicitly requested. This rules out the
hypothesis that Chrome/macOS silently downgrades attestation to `"none"` before
transmission (a real WebAuthn behavior when conveyance is `"none"`, but not
applicable here since `"direct"` was requested). Our x5c attestation object was
very likely transmitted to OpenAI's backend intact and genuinely evaluated — and
still produced `is_non_exportable_hardware_key: false`.

Other details worth keeping: resident/discoverable credential is **required**
(`requireResidentKey`/`residentKey: "required"`), `userVerification: "required"`,
both ES256 (`-7`) and RS256 (`-257`) are acceptable algorithms (clave only offers
`-7`, which is accepted), and the `prf` extension is requested (WebAuthn-level
PRF via CTAP2 `hmac-secret`) — clave does not implement real HMAC-secret key
agreement, only echoes a boolean; this is very unlikely to matter for the hardware
classification gate but is a known incompleteness.

### 3. The real CTAP2 wire request — `authenticatorMakeCredential` (from clave's own debug dump)

Decoded directly from the CBOR the daemon receives over USB HID (see
`debugDumpMakeCredentialParams` in `ctap2.go`, added for this investigation):

```
[1] clientDataHash = bytes(32)
[2] rp             = {id: openai.com, name: OpenAI}
[3] user           = {id: bytes(29), name: ..., displayName: ...}
[4] pubKeyCredParams = [{alg: -7, type: public-key}]
[5] excludeList    = [{id: bytes(16), type: public-key}, {id: bytes(20), type: public-key}]
[6] extensions     = {credProtect: 2}
[7] options        = {rk: true, uv: true}
```

Note param `[4]` here only lists `alg: -7` even though the browser-level creation
options listed both `-7` and `-257` — Chrome/the platform narrows this down before
talking CTAP2, unsurprising.

`credProtect: 2` (`userVerificationOptionalWithCredentialIDList`) is requested as a
CTAP2.1 extension. clave's response did not originally echo this (no `ED` flag,
no extension data in `authenticatorData`) — this was identified and fixed during
this investigation (see "Changes made" below). After the fix, OpenAI's response
still did not flip `is_non_exportable_hardware_key`, meaning credProtect compliance
was not the blocker either.

### 4. clave's response to makeCredential (v1.6.1, final tested state)

- `fmt: "packed"`
- `authData`: rpIdHash + flags(UP|UV|AT|ED) + signCount + AAGUID + credId + COSE pubkey + extensions(`{credProtect: 2, hmac-secret: true}` echoed)
- `attStmt`: `{alg: -7, sig: <ECDSA sig over authData+clientDataHash>, x5c: [<self-signed cert>]}`
- AAGUID tested as both a custom value (`4F70656E4649444C616E63656C6F74`,
  ASCII "OpenFIDOLancelot") and the real YubiKey 5C NFC / 5 NFC firmware 5.2/5.4
  AAGUID `2fc0579f-8113-47ea-b116-bb5a8db9202a`.
- The x5c certificate is **self-signed**, generated locally (`attest.go`), with a
  FIDO AAGUID X.509 extension (OID `1.3.6.1.4.1.45724.1.1.4`) matching the claimed
  AAGUID. It cannot and does not chain to any publicly trusted root.

### 5. OpenAI's production frontend bundle — `app-runtime-DI8szBs0.js` (1.17 MB, fetched directly from `auth-cdn.oaistatic.com`)

Grepped exhaustively for relevant strings:

- `required_auth_method: ws("nonexportable_hardware_key").optional()` — confirms
  the literal backend-API semantic name for what's required: a **"nonexportable
  hardware key."** This is the vocabulary OpenAI itself uses, not something we
  inferred.
- **Zero** occurrences of `aaguid` anywhere in the frontend bundle.
- **Zero** occurrences of `attestation` anywhere in the frontend bundle.
- `yubikey`/`Yubikey`/`YubiKey` occur **only** in analytics event names
  (`aasYubikeyOrderLinkClickedSuccess`, `aasYubikeyOrderLinkClickedFailure`) — i.e.
  "did the user click the Order YubiKeys link," not classification logic.

Conclusion from this: **both** the cosmetic model-name label and the actual
hardware-eligibility boolean are computed entirely server-side. There is no
client-side AAGUID allowlist or attestation-check logic shipped to the browser
that could be patched around (e.g. via a browser extension or MITM proxy on the
JS). Whatever decides `is_non_exportable_hardware_key` lives purely in OpenAI's
backend and is not observable or influenceable from the client beyond the WebAuthn
ceremony data itself.

### 6. External corroboration (community reports, not just our own experiments)

- [RS-Key](https://github.com/TheMaxMur/RS-Key/issues/128) — another DIY hardware
  FIDO2 project (Waveshare RP2350 / Raspberry Pi Pico 2 W) hit the identical wall:
  registers fine, classified as "Passkey," Continue stays disabled. Unsolved as of
  last check.
- [`voidnullvalue/openai-fido2`](https://github.com/voidnullvalue/openai-fido2) —
  an ESP32-S3 CTAP 2.1 hardware key built specifically for Daybreak. Author reports
  OpenAI Support said: **"MDS listing and attestation are not documented
  requirements," and there is "no documented arbitrary-AAGUID allowlist."**
  Support's suggested workaround was simply "use a different key." (Support reps
  likely don't know/won't state internal backend logic; take with a grain of salt,
  but it's consistent with "this isn't publicly specified, and isn't a simple
  AAGUID allowlist you can match by value alone.")
- [OpenAI community: TrustKey T110/T120 confirmed ineligible](https://community.openai.com/t/daybreak-trustkey-t110-t120-confirmed-ineligible-compatibility-requirements-were-clarified-too-late/1402777) —
  **critical data point**: TrustKey is a real, FIDO2-certified hardware vendor.
  Genuine hardware, genuine vendor-chained attestation, and OpenAI Support
  explicitly confirmed these models are **not eligible** for individual Daybreak
  access. This rules out "any cryptographically-valid FIDO2 hardware attestation
  passes" — the gate is narrower than generic FIDO MDS validity. The most likely
  explanation is a vendor-specific allowlist tied to OpenAI's Yubico business
  partnership (OpenAI sells a co-branded YubiKey bundle), not a neutral technical
  standard.
- [OpenAI × Yubico partnership announcement (FIDO Alliance)](https://fidoalliance.org/news-openai-and-yubico-partner-to-bring-custom-phishing-resistant-yubikeys-to-openai-users/) —
  confirms this is a named commercial partnership, not merely "Yubico happens to
  work because their attestation is well-formed."
- Chinese-language forum thread (linux.do, blocked by Cloudflare challenge from
  direct fetch, only indirectly summarized via search) described a "zero
  additional cost solution" — on closer look this turned out to be "register a
  software passkey as the second factor," which is explicitly against the stated
  Daybreak rule (hardware-only) and not a real bypass. Not useful.
- No Russian- or Spanish-language source added anything beyond the English
  community threads already cited; searches in those languages mostly surfaced
  machine-translated copies of the same English-language OpenAI community posts
  and official docs, plus generic FIDO2 setup guides with no bearing on this
  specific classification gate.

## What we changed in clave as part of this investigation (kept, useful regardless of the OpenAI outcome)

1. **Fixed a real, independent bug**: `ctaphid.go`'s `writePacket()` had no
   `EAGAIN`/`EWOULDBLOCK` retry loop on the non-blocking HID fd. A transiently busy
   USB IN endpoint caused the final CBOR response packet to be silently dropped,
   hanging the browser mid-ceremony forever. Fixed with the same polling pattern
   already used in `readPacket()`. This is a correctness fix, keep it.
2. **Learned**: `SIGKILL` (`kill -9`) on the clave daemon still panics the MTK
   kernel and reboots the device, *even with the non-blocking IO rewrite*, because
   SIGKILL bypasses the Go signal handler entirely and the kernel force-closes
   `/dev/hidg1` out from under the musb-hdrc driver with no warning. **Only
   `SIGTERM`/plain `kill <pid>` is safe.** Documented in
   `feedback_sigkill-panics-kernel` memory.
3. **Added `attest.go`**: persistent ECDSA P-256 attestation keypair + self-signed
   X.509 cert with a FIDO AAGUID extension, generated once and reused. Legitimate
   and useful for any RP that accepts self/basic attestation without strict chain
   validation (i.e. most non-Daybreak services: GitHub, Google, Microsoft, etc.).
4. **Added CTAP2.1 `credProtect`/`hmac-secret` extension echo** in
   `makeCredential` (sets the `ED` flag and appends extension CBOR to
   `authenticatorData` when the RP requests them). This is a genuine protocol
   compliance improvement independent of the OpenAI investigation — real FIDO2
   security keys echo requested extensions; clave didn't before. Worth keeping.
5. **Added a temporary full CBOR request dump** (`debugDumpMakeCredentialParams`
   in `ctap2.go`) that prints every key/value of an incoming
   `authenticatorMakeCredential` request to the daemon log. This is how we learned
   OpenAI requests `credProtect: 2`. Currently still present/enabled in the
   codebase (v1.6.1) — consider gating behind a `-debug` flag or removing before
   any public release, since it's verbose.
6. **AAGUID currently set to the YubiKey 5C NFC value**
   (`2fc0579f-8113-47ea-b116-bb5a8db9202a`) in the committed-but-uncommitted
   working tree as of this writing. This was for testing the "does a real vendor
   AAGUID + full compliance flip the server flag" hypothesis; it did not. There is
   an open design decision (see below) on whether to revert this to clave's own
   honest AAGUID (`4F70656E4649444C616E63656C6F74`, used in the last pushed commit
   `322c84d`) given it provides no real benefit for OpenAI and arguably shouldn't
   impersonate a specific commercial vendor to other RPs either.

## Design decision pending / open question for the next agent

**Should clave keep the spoofed YubiKey AAGUID, or revert to its own honest
identity?** Arguments either way:
- *Revert to honest AAGUID*: It provides zero benefit toward the actual
  `is_non_exportable_hardware_key` goal (proven by direct evidence above), and
  continuing to present as "YubiKey 5 Series with NFC" to *every* relying party
  (not just OpenAI) is a cosmetic impersonation with no functional upside anywhere
  it matters. The previously pushed commit (`322c84d`) already reverted to the
  honest AAGUID; the current *uncommitted* working tree re-applied the YubiKey
  AAGUID for one more combined test (YubiKey AAGUID + credProtect). That
  uncommitted state should probably be resolved (either commit it if keeping the
  spoof is still wanted for further experiments, or revert ctap2.go's `aaguid` var
  back to the custom value and commit that + the credProtect/debug-dump
  additions).
- *Keep spoofing*: Only a reason to keep it would be if a future experiment
  specifically needs the cosmetic YubiKey label for some reason (e.g. probing
  whether a *delay* or *re-verification* unlocks Continue after the label
  persists for some hours/days — untested, see below).

## What's left to try (low-probability, listed for completeness, not because any are expected to work)

These are the only remaining angles that don't require possessing Yubico's private
attestation key. None were tested due to time/low expected value, but a future
agent might:

1. **Time-delayed re-check**: It's conceivable `is_non_exportable_hardware_key`
   is computed asynchronously (a backend job that re-validates attestation some
   time after registration, e.g. against a periodically-refreshed FIDO MDS BLOB
   cache) rather than synchronously at registration time. Register, wait a few
   hours to a day, reload the page, and check if the flag changed without any new
   action. Low probability — the `created_at` timestamps observed were immediate
   and nothing in the UI suggested "pending verification," but not rigorously
   ruled out.
2. **Enterprise attestation (`ep` / epAtt)**: CTAP2.1 defines an "enterprise
   attestation" mode for managed-fleet scenarios where a specific RP ID is
   pre-authorized to receive uniquely-identifying attestation without the normal
   anonymization privacy concerns. clave's `getInfo` does not currently advertise
   an `ep` option, and the observed `authenticatorMakeCredential` request did not
   include an enterprise-attestation request (param `0x0A`), nor did OpenAI's
   `start.json` creation options show anything resembling an enterprise
   attestation flag. This looks like a dead end (OpenAI isn't signaling for it),
   but worth a final grep of a full CTAP2 request dump if revisited.
3. **PRF/hmac-secret full implementation**: clave currently only *echoes* the
   `hmac-secret`/`credProtect` extension request as a boolean; it does not
   implement the actual ECDH key-agreement + HMAC computation CTAP2's
   `hmac-secret` extension requires. If OpenAI's backend performs a live
   functional check (e.g. actually invoking the PRF extension during a follow-up
   assertion and checking the output is well-formed/stable), a non-functional stub
   could conceivably be detected. This seems unlikely to be *the* classification
   signal (the registration-time boolean is set before any assertion/PRF-use
   ceremony occurs), but implementing real hmac-secret is good protocol hygiene
   regardless and was not done due to time constraints.
4. **Contact OpenAI Support directly** asking for manual Daybreak eligibility
   review — not a technical fix, but the only avenue that has a nonzero track
   record (some community posts mention case-by-case exceptions), and doesn't
   require buying anything.

## What very likely will NOT work (ruled out with reasonable confidence)

- Any AAGUID value alone, real or fake — proven to only affect the cosmetic label.
- Any attestation `fmt` choice (`none`, `packed` self-attestation, `packed` with a
  self-signed x5c) — all tested, none flip the flag.
- Matching `getInfo` capability fields (extensions list, versions, transports,
  firmware version number) to a real YubiKey's reported capabilities — untested in
  isolation but very unlikely to matter given TrustKey (genuinely matching its own
  real capabilities) was still rejected.
- CTAP2.1 extension compliance (`credProtect`, `hmac-secret` boolean echo) — tested
  in combination with YubiKey AAGUID + x5c, no effect.
- Any client-side/browser trick (extension, proxy, patched frontend JS) — ruled
  out by direct inspection of the production bundle: the check is 100% server-side,
  nothing client-exploitable was found.
- Extracting or forging a real vendor's (Yubico's) private attestation CA key —
  **not pursued, and should not be pursued.** This would mean compromising a third
  party's cryptographic trust infrastructure (not just "my own device"), is almost
  certainly illegal (supply-chain/key-compromise territory), and even framed as
  "research" it's out of scope for this project. Any future agent asked to go down
  this path should decline for the same reason.

## Relevant files in this repo

- `ctap2.go` — CTAP2 protocol handler; `aaguid` var, `makeCredential`,
  `getAssertion`, `getInfo`, the credProtect/hmac-secret extension echo, and the
  (currently still present) `debugDumpMakeCredentialParams` debug dump.
- `attest.go` — persistent self-signed attestation keypair/cert generation.
- `ctaphid.go` — USB HID CTAPHID framing layer; non-blocking read/write with
  `EAGAIN` polling (the write-side fix from this investigation).
- `main.go` — CLI entry point, daemon bootstrap, signal handling
  (`SIGTERM`-only-safe shutdown), version constant (currently `1.6.1`,
  uncommitted).
- `gadget.go` — minimal USB HID device discovery/permissions helper (no runtime
  ConfigFS gadget manipulation — that's all in the Magisk module now).
- `magisk/clave-hid/service.sh` — Magisk `service.sh` (boot_completed-triggered)
  that creates the USB HID gadget function at boot. Replaced an earlier
  `post-fs-data.sh` approach that ran too early and broke USB/ADB.
- `README.md`, `SECURITY.md` — project docs, should be kept in sync with any
  further architecture changes.
- `start.json`, `finish.json`, `delete.json`, `initialize.json` (in
  `/Users/thekeenest/yubi/`, **not** inside the git repo — these are captured
  OpenAI API payloads saved by the user from DevTools, kept outside the repo
  intentionally since they contain account-specific identifiers). `initialize.json`
  turned out to be an unrelated Statsig feature-gate blob, not useful.

## Device/deployment context (see also local Claude memory files)

- Target device: Xiaomi Redmi 9 (`lancelot`, MT6768), rooted with Magisk, custom
  LineageOS-based ROM.
- Daemon binary cross-compiled with `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`,
  pushed via `adb push`, run manually via `adb shell su -c 'nohup ... &'` during
  development (the Magisk module only sets up the USB HID gadget at boot; it does
  not yet auto-start the daemon itself — confirm this is/isn't desired for a
  "finished" deployment).
- `adb shell su -c 'kill -15 <pid>'` is the **only** safe way to stop the running
  daemon during development. Never `kill -9`.
- Memory files with durable cross-session knowledge (outside this repo, at
  `/Users/thekeenest/.claudenl/projects/-Users-thekeenest-yubi/memory/`):
  `feedback_adb-safety.md`, `feedback_test-before-deploy.md`,
  `feedback_sigkill-panics-kernel.md`, `project_clave-architecture.md`,
  `project_clave-openai-aaguid.md` (now superseded/expanded by this document —
  consider merging), `user_device-owner.md`, `reference_clave-emergency.md`.
