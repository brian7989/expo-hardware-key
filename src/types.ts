/**
 * The security level of a hardware key.
 *
 * - `secure-enclave`     iOS Secure Enclave or Android StrongBox — dedicated
 *                        security chip, keys never leave the hardware boundary.
 * - `trusted-execution`  Android TEE (software-isolated on the main SoC) —
 *                        hardware-backed but no dedicated chip.
 * - `software`           Simulator / old devices — keys managed in software only.
 *                        Never use in production for sensitive operations.
 */
export type SecurityLevel = 'secure-enclave' | 'trusted-execution' | 'software';

export interface KeyOptions {
  /**
   * Require biometric authentication (Face ID / fingerprint) before each
   * signing operation.
   *
   * @default false
   */
  requireBiometrics?: boolean;

  /**
   * Invalidate this key if the user enrolls a new biometric (adds a finger,
   * re-registers Face ID). Recommended for high-security applications.
   *
   * Only meaningful when `requireBiometrics` is `true`.
   *
   * @default false
   */
  invalidateOnNewBiometric?: boolean;

  /**
   * Custom message shown in the biometric prompt.
   * Falls back to a sensible default if not provided.
   */
  biometricPrompt?: string;
}

export interface PublicKeyInfo {
  /** The key identifier used to create this key. */
  keyId: string;
  /**
   * 33-byte compressed P-256 public key.
   * Format: `[0x02 or 0x03][32-byte X coordinate]`
   */
  publicKey: Uint8Array;
  /** Always `"P-256"` — the only curve supported by Apple SE and Android Keystore. */
  algorithm: 'P-256';
  /** Where the private key lives. */
  securityLevel: SecurityLevel;
}

export const HardwareKeyErrorCode = {
  /** The requested key ID does not exist in the keystore. */
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  /** A key with this ID already exists. Delete it first or use a different ID. */
  KEY_ALREADY_EXISTS: 'KEY_ALREADY_EXISTS',
  /** The user cancelled the biometric prompt. */
  BIOMETRIC_CANCELLED: 'BIOMETRIC_CANCELLED',
  /** Too many failed biometric attempts — the sensor is temporarily locked. */
  BIOMETRIC_LOCKOUT: 'BIOMETRIC_LOCKOUT',
  /** No biometrics are enrolled on this device. */
  BIOMETRIC_NOT_ENROLLED: 'BIOMETRIC_NOT_ENROLLED',
  /**
   * The key was invalidated because the user enrolled a new biometric.
   * The app must generate a new key and re-register the public key with the server.
   */
  KEY_INVALIDATED: 'KEY_INVALIDATED',
  /** The hardware security element is unavailable (e.g. device restart, thermal). */
  HARDWARE_UNAVAILABLE: 'HARDWARE_UNAVAILABLE',
  /** The current device/OS does not support hardware-backed key operations. */
  NOT_SUPPORTED: 'NOT_SUPPORTED',
  /** An unexpected error occurred in the native layer. */
  UNKNOWN: 'UNKNOWN',
} as const;

export type HardwareKeyErrorCode = (typeof HardwareKeyErrorCode)[keyof typeof HardwareKeyErrorCode];

/** All errors thrown by expo-hardware-key. Switch on `.code` for handling. */
export class HardwareKeyError extends Error {
  readonly code: HardwareKeyErrorCode;

  constructor(message: string, code: HardwareKeyErrorCode) {
    super(message);
    this.name = 'HardwareKeyError';
    this.code = code;
  }

  /** Create a `HardwareKeyError` from a raw native error string. */
  static fromNative(code: string, message: string): HardwareKeyError {
    const safeCode = isHardwareKeyErrorCode(code) ? code : HardwareKeyErrorCode.UNKNOWN;
    return new HardwareKeyError(message, safeCode);
  }
}

function isHardwareKeyErrorCode(code: string): code is HardwareKeyErrorCode {
  return Object.values(HardwareKeyErrorCode).includes(code as HardwareKeyErrorCode);
}
