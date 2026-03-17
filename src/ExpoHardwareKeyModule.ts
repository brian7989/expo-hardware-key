import { NativeModule, requireNativeModule } from 'expo';

/**
 * Shape of the native module as exposed from Swift / Kotlin.
 *
 * All methods pass raw Base64-encoded byte arrays across the JS bridge
 * (JSI Uint8Array support varies by Expo/RN version; Base64 is universal).
 * The public TypeScript API in `index.ts` converts to/from `Uint8Array`.
 */
declare class ExpoHardwareKeyNativeModule extends NativeModule<Record<string, never>> {
  /**
   * Generate a P-256 key pair inside the hardware security element.
   * Returns the compressed public key as a Base64 string.
   */
  generateKey(
    keyId: string,
    requireBiometrics: boolean,
    invalidateOnNewBiometric: boolean,
    biometricPrompt: string,
  ): Promise<{ publicKeyBase64: string; securityLevel: string }>;

  /**
   * Sign `dataBase64` with the private key for `keyId`.
   * The hardware performs SHA-256 hashing internally.
   * Returns raw 64-byte r||s as Base64.
   */
  sign(keyId: string, dataBase64: string, biometricPrompt: string): Promise<string>;

  /**
   * Return the compressed public key for `keyId` as Base64.
   */
  getPublicKey(keyId: string): Promise<{ publicKeyBase64: string; securityLevel: string }>;

  /**
   * Return `true` if a key with `keyId` exists in the keystore.
   */
  keyExists(keyId: string): Promise<boolean>;

  /**
   * Delete the key for `keyId`. No-op if the key does not exist.
   */
  deleteKey(keyId: string): Promise<void>;

  /**
   * Return `true` if hardware-backed key generation is available on this device.
   */
  isHardwareBackedAvailable(): Promise<boolean>;
}

export default requireNativeModule<ExpoHardwareKeyNativeModule>('ExpoHardwareKey');
