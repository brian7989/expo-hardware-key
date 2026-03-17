# Changelog

## 0.1.0

Initial release.

- P-256 key pair generation in iOS Secure Enclave and Android Keystore/StrongBox
- ECDSA signing with SHA-256 (hardware performs hashing)
- Biometric gating with optional key invalidation on new enrollment
- 64-byte raw r||s signature format (consistent across platforms)
- Compressed public key export (33 bytes)
- Software mock for unit testing (`expo-hardware-key/mock`)
- Web stub (throws `NOT_SUPPORTED`)
