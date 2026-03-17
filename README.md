# expo-hardware-key

Hardware-backed P-256 key generation and ECDSA signing for React Native. Private keys live in the iOS Secure Enclave or Android Keystore/StrongBox and never leave hardware.

## Installation

```bash
npx expo install expo-hardware-key
```

## Usage

```typescript
import { generateKey, sign, getPublicKey, keyExists, deleteKey } from 'expo-hardware-key';

const { publicKey, securityLevel } = await generateKey('user-key', {
  requireBiometrics: true,
  invalidateOnNewBiometric: true,
});

const signature = await sign('user-key', data);
// 64-byte Uint8Array (raw r||s)

await deleteKey('user-key');
```

## API

| Function | Description |
|----------|-------------|
| `generateKey(keyId, options?)` | Generate a P-256 key pair in hardware. Returns compressed public key + security level. |
| `sign(keyId, data, options?)` | Sign raw bytes. Pass unhashed data -- hardware does SHA-256. Returns 64-byte r\|\|s. |
| `getPublicKey(keyId)` | Get public key info for an existing key. |
| `keyExists(keyId)` | Check if a key exists. No biometric required. |
| `deleteKey(keyId)` | Delete a key. Irreversible. No-op if missing. |
| `isHardwareBackedAvailable()` | `false` on simulators, old devices, and web. |

**`generateKey` options:** `requireBiometrics` (default `false`), `invalidateOnNewBiometric` (default `false`), `biometricPrompt` (custom prompt string).

## Error handling

All errors are `HardwareKeyError` instances. Switch on `.code`:

`KEY_NOT_FOUND` | `KEY_ALREADY_EXISTS` | `BIOMETRIC_CANCELLED` | `BIOMETRIC_LOCKOUT` | `BIOMETRIC_NOT_ENROLLED` | `KEY_INVALIDATED` | `HARDWARE_UNAVAILABLE` | `NOT_SUPPORTED` | `UNKNOWN`

## Testing

```typescript
jest.mock('expo-hardware-key', () => require('expo-hardware-key/mock').mockModule);
```

Pure-JS P-256 mock via `@noble/curves`. In-memory keys, `securityLevel: 'software'`, no biometric prompts.

## Platform support

| | iOS | Android |
|---|---|---|
| Hardware | Secure Enclave | StrongBox / TEE |
| Min version | 15.1 | API 23 |

## Security

See [SECURITY.md](./SECURITY.md).

## License

MIT
