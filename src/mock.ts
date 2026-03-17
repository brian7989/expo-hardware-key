// Software mock of expo-hardware-key using @noble/curves P-256.
// Use in Jest/Node tests where native hardware is unavailable.

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { HardwareKeyError, HardwareKeyErrorCode } from './types';
import type { KeyOptions, PublicKeyInfo, SecurityLevel } from './types';

// In-memory key store
const keyStore = new Map<string, Uint8Array>(); // keyId → private key scalar (32 bytes)

function requireKey(keyId: string): Uint8Array {
  const priv = keyStore.get(keyId);
  if (!priv) {
    throw new HardwareKeyError(`Key '${keyId}' not found`, HardwareKeyErrorCode.KEY_NOT_FOUND);
  }
  return priv;
}

function toPublicKeyInfo(keyId: string, privateKey: Uint8Array): PublicKeyInfo {
  const pubPoint = p256.getPublicKey(privateKey, true); // compressed = true → 33 bytes
  return {
    keyId,
    publicKey: pubPoint,
    algorithm: 'P-256',
    securityLevel: 'software' as SecurityLevel,
  };
}

export async function generateKey(keyId: string, _options: KeyOptions = {}): Promise<PublicKeyInfo> {
  if (keyStore.has(keyId)) {
    throw new HardwareKeyError(
      `Key '${keyId}' already exists — delete it first`,
      HardwareKeyErrorCode.KEY_ALREADY_EXISTS,
    );
  }
  const privateKey = p256.utils.randomSecretKey();
  keyStore.set(keyId, privateKey);
  return toPublicKeyInfo(keyId, privateKey);
}

export async function sign(
  keyId: string,
  data: Uint8Array,
  _options: Pick<KeyOptions, 'biometricPrompt'> = {},
): Promise<Uint8Array> {
  const privateKey = requireKey(keyId);
  const hash = sha256(data);
  const sig = p256.sign(hash, privateKey, { prehash: false });
  return new Uint8Array(sig);
}

export async function getPublicKey(keyId: string): Promise<PublicKeyInfo> {
  const privateKey = requireKey(keyId);
  return toPublicKeyInfo(keyId, privateKey);
}

export async function keyExists(keyId: string): Promise<boolean> {
  return keyStore.has(keyId);
}

export async function deleteKey(keyId: string): Promise<void> {
  keyStore.delete(keyId);
}

export async function isHardwareBackedAvailable(): Promise<boolean> {
  return false; // always software in mock
}

export function clearAllKeys(): void {
  keyStore.clear();
}

export { HardwareKeyError, HardwareKeyErrorCode };
export type { KeyOptions, PublicKeyInfo, SecurityLevel };

/** Drop-in jest.mock() replacement for 'expo-hardware-key'. */
export const mockModule = {
  generateKey,
  sign,
  getPublicKey,
  keyExists,
  deleteKey,
  isHardwareBackedAvailable,
  clearAllKeys,
  HardwareKeyError,
  HardwareKeyErrorCode,
};
