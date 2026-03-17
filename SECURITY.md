# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.x     | Yes       |

## Design

Private keys never leave the hardware boundary. JS code is untrusted with respect to key material.

| Property | Status | Notes |
|----------|--------|-------|
| Private key non-extractability | Yes | Keys generated inside SE/TEE; never passed to JS |
| Hardware attestation | No | Use Android Key Attestation or Apple DeviceCheck |
| Biometric gating | Yes | Enforced by the OS, not JS |
| Key invalidation on biometric change | Yes | `invalidateOnNewBiometric: true` |
| Signature format | Yes | 64-byte raw r||s, consistent across platforms |

**Crypto:** P-256 ECDSA with SHA-256. iOS uses `SecKeyCreateSignature(.ecdsaSignatureDigestX962SHA256)`. Android uses `NONEwithECDSA` on a pre-hashed SHA-256 digest.

**Mock:** `expo-hardware-key/mock` is pure-JS (`@noble/curves`). No hardware guarantees. Testing only.

## Reporting a Vulnerability

Do not open a public issue. Report via [GitHub Security Advisory](https://github.com/briantslee/expo-hardware-key/security/advisories/new) or email **brian.ts.lee.0907@gmail.com** with subject `[expo-hardware-key] Security Issue`.

Response times: acknowledgement within 48 hours, status update within 7 days.
