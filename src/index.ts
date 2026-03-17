import NativeModule from './ExpoHardwareKeyModule';
import { HardwareKeyError, HardwareKeyErrorCode } from './types';
import type { KeyOptions, PublicKeyInfo, SecurityLevel } from './types';

export { HardwareKeyError, HardwareKeyErrorCode };
export type { KeyOptions, PublicKeyInfo, SecurityLevel };

// Encoding

function base64FromBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function bytesFromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Native result mapping

function toSecurityLevel(raw: string): SecurityLevel {
  if (raw === 'secure-enclave' || raw === 'trusted-execution' || raw === 'software') {
    return raw;
  }
  return 'software';
}

function hasErrorCode(err: unknown): err is Error & { code: string } {
  return (
    err instanceof Error &&
    'code' in err &&
    typeof (err as Record<string, unknown>).code === 'string'
  );
}

function normalizeError(err: unknown): never {
  if (err instanceof HardwareKeyError) throw err;
  if (hasErrorCode(err)) {
    throw HardwareKeyError.fromNative(err.code, err.message);
  }
  throw HardwareKeyError.fromNative(HardwareKeyErrorCode.UNKNOWN, String(err));
}

function buildPublicKeyInfo(
  keyId: string,
  result: { publicKeyBase64: string; securityLevel: string },
): PublicKeyInfo {
  return {
    keyId,
    publicKey: bytesFromBase64(result.publicKeyBase64),
    algorithm: 'P-256',
    securityLevel: toSecurityLevel(result.securityLevel),
  };
}

// Public API

/**
 * Generate a P-256 key pair inside the device hardware security element.
 * The private key never leaves the hardware boundary.
 *
 * @throws {HardwareKeyError} `KEY_ALREADY_EXISTS` if the key already exists.
 * @throws {HardwareKeyError} `NOT_SUPPORTED` on web or unsupported devices.
 */
export async function generateKey(keyId: string, options: KeyOptions = {}): Promise<PublicKeyInfo> {
  try {
    const result = await NativeModule.generateKey(
      keyId,
      options.requireBiometrics ?? false,
      options.invalidateOnNewBiometric ?? false,
      options.biometricPrompt ?? 'Authenticate to generate your secure key',
    );
    return buildPublicKeyInfo(keyId, result);
  } catch (err) {
    normalizeError(err);
  }
}

/**
 * Sign `data` with the private key stored under `keyId`.
 *
 * Pass the original unhashed data -- the hardware performs SHA-256 internally.
 * Returns a raw 64-byte r||s signature (no DER, no recovery byte).
 *
 * @throws {HardwareKeyError} `KEY_NOT_FOUND` if the key does not exist.
 * @throws {HardwareKeyError} `BIOMETRIC_CANCELLED` if the user dismissed the prompt.
 */
export async function sign(
  keyId: string,
  data: Uint8Array,
  options: Pick<KeyOptions, 'biometricPrompt'> = {},
): Promise<Uint8Array> {
  try {
    const dataBase64 = base64FromBytes(data);
    const sigBase64 = await NativeModule.sign(
      keyId,
      dataBase64,
      options.biometricPrompt ?? 'Authenticate to sign',
    );
    return bytesFromBase64(sigBase64);
  } catch (err) {
    normalizeError(err);
  }
}

/**
 * Return the public key info for an existing key.
 *
 * @throws {HardwareKeyError} `KEY_NOT_FOUND` if the key does not exist.
 */
export async function getPublicKey(keyId: string): Promise<PublicKeyInfo> {
  try {
    const result = await NativeModule.getPublicKey(keyId);
    return buildPublicKeyInfo(keyId, result);
  } catch (err) {
    normalizeError(err);
  }
}

/** Return `true` if a key with `keyId` exists in the keystore. */
export async function keyExists(keyId: string): Promise<boolean> {
  try {
    return await NativeModule.keyExists(keyId);
  } catch (err) {
    normalizeError(err);
  }
}

/**
 * Delete the key stored under `keyId`. Irreversible.
 * Safe to call if the key does not exist (no-op).
 */
export async function deleteKey(keyId: string): Promise<void> {
  try {
    await NativeModule.deleteKey(keyId);
  } catch (err) {
    normalizeError(err);
  }
}

/**
 * Return `true` if this device supports hardware-backed key generation.
 * Returns `false` on simulators, very old Android devices, and web.
 */
export async function isHardwareBackedAvailable(): Promise<boolean> {
  try {
    return await NativeModule.isHardwareBackedAvailable();
  } catch {
    return false;
  }
}
