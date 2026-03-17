// Web stub — all key operations throw NOT_SUPPORTED.
import { HardwareKeyError, HardwareKeyErrorCode } from './types';

function notSupported(): never {
  throw new HardwareKeyError('Not supported on web', HardwareKeyErrorCode.NOT_SUPPORTED);
}

export default {
  generateKey: notSupported,
  sign: notSupported,
  getPublicKey: notSupported,
  keyExists: async (_keyId: string) => false,
  deleteKey: async (_keyId: string) => { /* no-op */ },
  isHardwareBackedAvailable: async () => false,
};
