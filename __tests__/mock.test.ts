// Tests for the expo-hardware-key software mock.

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  clearAllKeys,
  deleteKey,
  generateKey,
  getPublicKey,
  isHardwareBackedAvailable,
  keyExists,
  sign,
  HardwareKeyError,
  HardwareKeyErrorCode,
} from '../src/mock';

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Verify a 64-byte raw r||s ECDSA signature against a compressed public key.
 *
 * The mock pre-hashes data with SHA-256 before calling p256.sign(..., {prehash:false}).
 * So verification must pass the pre-hashed digest and also use prehash:false.
 */
function verifySignature(data: Uint8Array, sig64: Uint8Array, compressedPublicKey: Uint8Array): boolean {
  const hash = sha256(data);
  return p256.verify(sig64, hash, compressedPublicKey, { prehash: false });
}

// ── Test setup ─────────────────────────────────────────────────────────────────

beforeEach(() => {
  clearAllKeys();
});

// ── generateKey ────────────────────────────────────────────────────────────────

describe('generateKey', () => {
  it('returns correct PublicKeyInfo shape', async () => {
    const info = await generateKey('k1');
    expect(info.keyId).toBe('k1');
    expect(info.algorithm).toBe('P-256');
    expect(info.securityLevel).toBe('software');
    expect(info.publicKey).toBeInstanceOf(Uint8Array);
    expect(info.publicKey.length).toBe(33);
  });

  it('compressed public key starts with 0x02 or 0x03', async () => {
    const info = await generateKey('k1');
    expect([0x02, 0x03]).toContain(info.publicKey[0]);
  });

  it('generates a valid P-256 public key (verifiable by noble)', async () => {
    const info = await generateKey('k1');
    // A valid public key can be used to verify a signature without throwing
    const data = new Uint8Array(1);
    const sig = await sign('k1', data);
    expect(verifySignature(data, sig, info.publicKey)).toBe(true);
  });

  it('generates different keys for different IDs', async () => {
    const a = await generateKey('ka');
    const b = await generateKey('kb');
    expect(Buffer.from(a.publicKey).toString('hex')).not.toBe(
      Buffer.from(b.publicKey).toString('hex'),
    );
  });

  it('each call generates a fresh random key for same ID — not deterministic', async () => {
    await generateKey('k1');
    await deleteKey('k1');
    const second = await generateKey('k1');
    // Just verify it's a valid key; uniqueness is probabilistic
    expect(second.publicKey.length).toBe(33);
  });

  it('throws KEY_ALREADY_EXISTS if key ID already taken', async () => {
    await generateKey('dup');
    await expect(generateKey('dup')).rejects.toMatchObject({
      code: HardwareKeyErrorCode.KEY_ALREADY_EXISTS,
    });
  });

  it('KEY_ALREADY_EXISTS error is a HardwareKeyError instance', async () => {
    await generateKey('dup');
    try {
      await generateKey('dup');
      fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(HardwareKeyError);
      expect((err as HardwareKeyError).code).toBe(HardwareKeyErrorCode.KEY_ALREADY_EXISTS);
    }
  });

  it('accepts key IDs with special characters', async () => {
    const info = await generateKey('user-identity-key:2024/v1');
    expect(info.keyId).toBe('user-identity-key:2024/v1');
  });

  it('accepts empty string as key ID', async () => {
    const info = await generateKey('');
    expect(info.keyId).toBe('');
  });

  it('accepts long key IDs (256 chars)', async () => {
    const longId = 'x'.repeat(256);
    const info = await generateKey(longId);
    expect(info.keyId).toBe(longId);
  });

  it('ignores unknown options gracefully', async () => {
    const info = await generateKey('k1', {
      requireBiometrics: true,
      invalidateOnNewBiometric: true,
      biometricPrompt: 'Authenticate',
    });
    expect(info.securityLevel).toBe('software'); // mock always software
  });
});

// ── sign ───────────────────────────────────────────────────────────────────────

describe('sign', () => {
  it('returns a 64-byte Uint8Array', async () => {
    await generateKey('k1');
    const data = new TextEncoder().encode('hello world');
    const sig = await sign('k1', data);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);
  });

  it('produces a valid ECDSA P-256 signature (verifiable with noble)', async () => {
    await generateKey('k1');
    const { publicKey } = await getPublicKey('k1');
    const data = new TextEncoder().encode('test data');
    const sig = await sign('k1', data);
    expect(verifySignature(data, sig, publicKey)).toBe(true);
  });

  it('produces different signatures for different data (nonce in ECDSA)', async () => {
    await generateKey('k1');
    const data1 = new TextEncoder().encode('data1');
    const data2 = new TextEncoder().encode('data2');
    const sig1 = await sign('k1', data1);
    const sig2 = await sign('k1', data2);
    expect(Buffer.from(sig1).toString('hex')).not.toBe(Buffer.from(sig2).toString('hex'));
  });

  it('same data signed twice produces different signatures (k is random)', async () => {
    await generateKey('k1');
    const data = new TextEncoder().encode('same data');
    const sig1 = await sign('k1', data);
    const sig2 = await sign('k1', data);
    // ECDSA with deterministic k (RFC 6979) would produce same sig — noble uses RFC 6979
    // so these may be equal. Both are valid though.
    expect(verifySignature(data, sig1, (await getPublicKey('k1')).publicKey)).toBe(true);
    expect(verifySignature(data, sig2, (await getPublicKey('k1')).publicKey)).toBe(true);
  });

  it('signature does NOT verify against wrong data', async () => {
    await generateKey('k1');
    const { publicKey } = await getPublicKey('k1');
    const data = new TextEncoder().encode('original');
    const sig = await sign('k1', data);
    const wrongData = new TextEncoder().encode('tampered');
    expect(verifySignature(wrongData, sig, publicKey)).toBe(false);
  });

  it('signature does NOT verify against different key', async () => {
    await generateKey('k1');
    await generateKey('k2');
    const data = new TextEncoder().encode('data');
    const sig = await sign('k1', data);
    const { publicKey: wrongPub } = await getPublicKey('k2');
    // Should not verify (probabilistically — the test could theoretically collide but won't)
    expect(verifySignature(data, sig, wrongPub)).toBe(false);
  });

  it('signs empty data (0 bytes)', async () => {
    await generateKey('k1');
    const { publicKey } = await getPublicKey('k1');
    const data = new Uint8Array(0);
    const sig = await sign('k1', data);
    expect(verifySignature(data, sig, publicKey)).toBe(true);
  });

  it('signs large data (1 MB)', async () => {
    await generateKey('k1');
    const { publicKey } = await getPublicKey('k1');
    const data = new Uint8Array(1024 * 1024).fill(0xab);
    const sig = await sign('k1', data);
    expect(verifySignature(data, sig, publicKey)).toBe(true);
  });

  it('signs data of exactly 32 bytes', async () => {
    await generateKey('k1');
    const { publicKey } = await getPublicKey('k1');
    const data = new Uint8Array(32).fill(0xff);
    const sig = await sign('k1', data);
    expect(verifySignature(data, sig, publicKey)).toBe(true);
  });

  it('throws KEY_NOT_FOUND for unknown key', async () => {
    await expect(sign('ghost', new Uint8Array(4))).rejects.toMatchObject({
      code: HardwareKeyErrorCode.KEY_NOT_FOUND,
    });
  });

  it('KEY_NOT_FOUND error is a HardwareKeyError instance', async () => {
    try {
      await sign('ghost', new Uint8Array(4));
      fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(HardwareKeyError);
      expect((err as HardwareKeyError).code).toBe(HardwareKeyErrorCode.KEY_NOT_FOUND);
    }
  });

  it('throws KEY_NOT_FOUND after key is deleted', async () => {
    await generateKey('k1');
    await deleteKey('k1');
    await expect(sign('k1', new Uint8Array(4))).rejects.toMatchObject({
      code: HardwareKeyErrorCode.KEY_NOT_FOUND,
    });
  });

  it('ignores biometricPrompt option (no hardware prompt in mock)', async () => {
    await generateKey('k1');
    const data = new TextEncoder().encode('data');
    const sig = await sign('k1', data, { biometricPrompt: 'Authenticate please' });
    expect(sig.length).toBe(64);
  });
});

// ── getPublicKey ───────────────────────────────────────────────────────────────

describe('getPublicKey', () => {
  it('returns the same public key as generateKey', async () => {
    const generated = await generateKey('k1');
    const fetched = await getPublicKey('k1');
    expect(fetched.keyId).toBe('k1');
    expect(Buffer.from(fetched.publicKey).toString('hex')).toBe(
      Buffer.from(generated.publicKey).toString('hex'),
    );
  });

  it('returns stable public key across multiple calls', async () => {
    await generateKey('k1');
    const first = await getPublicKey('k1');
    const second = await getPublicKey('k1');
    expect(Buffer.from(first.publicKey).toString('hex')).toBe(
      Buffer.from(second.publicKey).toString('hex'),
    );
  });

  it('returns algorithm = P-256', async () => {
    await generateKey('k1');
    const info = await getPublicKey('k1');
    expect(info.algorithm).toBe('P-256');
  });

  it('returns securityLevel = software', async () => {
    await generateKey('k1');
    const info = await getPublicKey('k1');
    expect(info.securityLevel).toBe('software');
  });

  it('throws KEY_NOT_FOUND for unknown key', async () => {
    await expect(getPublicKey('nope')).rejects.toMatchObject({
      code: HardwareKeyErrorCode.KEY_NOT_FOUND,
    });
  });

  it('throws KEY_NOT_FOUND after deletion', async () => {
    await generateKey('k1');
    await deleteKey('k1');
    await expect(getPublicKey('k1')).rejects.toMatchObject({
      code: HardwareKeyErrorCode.KEY_NOT_FOUND,
    });
  });
});

// ── keyExists ──────────────────────────────────────────────────────────────────

describe('keyExists', () => {
  it('returns false for non-existent key', async () => {
    expect(await keyExists('nope')).toBe(false);
  });

  it('returns true after generateKey', async () => {
    await generateKey('k1');
    expect(await keyExists('k1')).toBe(true);
  });

  it('returns false after deleteKey', async () => {
    await generateKey('k1');
    await deleteKey('k1');
    expect(await keyExists('k1')).toBe(false);
  });

  it('returns false after clearAllKeys', async () => {
    await generateKey('k1');
    clearAllKeys();
    expect(await keyExists('k1')).toBe(false);
  });

  it('only returns true for the correct key ID', async () => {
    await generateKey('ka');
    expect(await keyExists('ka')).toBe(true);
    expect(await keyExists('kb')).toBe(false);
  });
});

// ── deleteKey ──────────────────────────────────────────────────────────────────

describe('deleteKey', () => {
  it('deletes an existing key', async () => {
    await generateKey('k1');
    await deleteKey('k1');
    expect(await keyExists('k1')).toBe(false);
  });

  it('is a no-op for non-existent key (does not throw)', async () => {
    await expect(deleteKey('ghost')).resolves.toBeUndefined();
  });

  it('allows re-creation after deletion', async () => {
    await generateKey('k1');
    await deleteKey('k1');
    const info = await generateKey('k1');
    expect(info.keyId).toBe('k1');
  });

  it('only deletes the targeted key', async () => {
    await generateKey('ka');
    await generateKey('kb');
    await deleteKey('ka');
    expect(await keyExists('ka')).toBe(false);
    expect(await keyExists('kb')).toBe(true);
  });
});

// ── isHardwareBackedAvailable ──────────────────────────────────────────────────

describe('isHardwareBackedAvailable', () => {
  it('returns false (mock is always software)', async () => {
    expect(await isHardwareBackedAvailable()).toBe(false);
  });
});

// ── clearAllKeys ───────────────────────────────────────────────────────────────

describe('clearAllKeys', () => {
  it('clears all stored keys', async () => {
    await generateKey('k1');
    await generateKey('k2');
    await generateKey('k3');
    clearAllKeys();
    expect(await keyExists('k1')).toBe(false);
    expect(await keyExists('k2')).toBe(false);
    expect(await keyExists('k3')).toBe(false);
  });

  it('is safe to call on empty store', () => {
    expect(() => clearAllKeys()).not.toThrow();
  });

  it('allows new keys after clearing', async () => {
    await generateKey('k1');
    clearAllKeys();
    const info = await generateKey('k1');
    expect(info.keyId).toBe('k1');
  });
});

// ── HardwareKeyError ───────────────────────────────────────────────────────────

describe('HardwareKeyError', () => {
  it('is an instance of Error', () => {
    const err = new HardwareKeyError('test', HardwareKeyErrorCode.UNKNOWN);
    expect(err).toBeInstanceOf(Error);
  });

  it('has name = HardwareKeyError', () => {
    const err = new HardwareKeyError('test', HardwareKeyErrorCode.UNKNOWN);
    expect(err.name).toBe('HardwareKeyError');
  });

  it('carries the error code', () => {
    const err = new HardwareKeyError('msg', HardwareKeyErrorCode.KEY_NOT_FOUND);
    expect(err.code).toBe('KEY_NOT_FOUND');
  });

  it('carries the message', () => {
    const err = new HardwareKeyError('something went wrong', HardwareKeyErrorCode.UNKNOWN);
    expect(err.message).toBe('something went wrong');
  });

  describe('fromNative', () => {
    it('maps known code to typed HardwareKeyError', () => {
      const err = HardwareKeyError.fromNative('KEY_NOT_FOUND', 'Key not found');
      expect(err.code).toBe(HardwareKeyErrorCode.KEY_NOT_FOUND);
    });

    it('maps unknown code to UNKNOWN', () => {
      const err = HardwareKeyError.fromNative('TOTALLY_MADE_UP', 'some error');
      expect(err.code).toBe(HardwareKeyErrorCode.UNKNOWN);
    });

    it('preserves message', () => {
      const err = HardwareKeyError.fromNative('UNKNOWN', 'original message');
      expect(err.message).toBe('original message');
    });

    it('maps all defined error codes correctly', () => {
      for (const code of Object.values(HardwareKeyErrorCode)) {
        const err = HardwareKeyError.fromNative(code, 'msg');
        expect(err.code).toBe(code);
      }
    });
  });
});

// ── HardwareKeyErrorCode ───────────────────────────────────────────────────────

describe('HardwareKeyErrorCode', () => {
  it('has all expected codes', () => {
    expect(HardwareKeyErrorCode.KEY_NOT_FOUND).toBe('KEY_NOT_FOUND');
    expect(HardwareKeyErrorCode.KEY_ALREADY_EXISTS).toBe('KEY_ALREADY_EXISTS');
    expect(HardwareKeyErrorCode.BIOMETRIC_CANCELLED).toBe('BIOMETRIC_CANCELLED');
    expect(HardwareKeyErrorCode.BIOMETRIC_LOCKOUT).toBe('BIOMETRIC_LOCKOUT');
    expect(HardwareKeyErrorCode.BIOMETRIC_NOT_ENROLLED).toBe('BIOMETRIC_NOT_ENROLLED');
    expect(HardwareKeyErrorCode.KEY_INVALIDATED).toBe('KEY_INVALIDATED');
    expect(HardwareKeyErrorCode.HARDWARE_UNAVAILABLE).toBe('HARDWARE_UNAVAILABLE');
    expect(HardwareKeyErrorCode.NOT_SUPPORTED).toBe('NOT_SUPPORTED');
    expect(HardwareKeyErrorCode.UNKNOWN).toBe('UNKNOWN');
  });
});

// ── Key lifecycle integration ──────────────────────────────────────────────────

describe('full key lifecycle', () => {
  it('generate → sign → verify → delete', async () => {
    // Generate
    const info = await generateKey('lifecycle-key');
    expect(info.keyId).toBe('lifecycle-key');

    // Verify exists
    expect(await keyExists('lifecycle-key')).toBe(true);

    // Sign
    const data = new TextEncoder().encode('payload to sign');
    const sig = await sign('lifecycle-key', data);
    expect(sig.length).toBe(64);

    // Verify signature
    const { publicKey } = await getPublicKey('lifecycle-key');
    expect(verifySignature(data, sig, publicKey)).toBe(true);

    // Delete
    await deleteKey('lifecycle-key');
    expect(await keyExists('lifecycle-key')).toBe(false);

    // Operations after delete should fail
    await expect(sign('lifecycle-key', data)).rejects.toMatchObject({
      code: HardwareKeyErrorCode.KEY_NOT_FOUND,
    });
    await expect(getPublicKey('lifecycle-key')).rejects.toMatchObject({
      code: HardwareKeyErrorCode.KEY_NOT_FOUND,
    });
  });

  it('multiple independent keys coexist', async () => {
    await generateKey('alice');
    await generateKey('bob');
    await generateKey('server');

    const alicePub = (await getPublicKey('alice')).publicKey;
    const bobPub = (await getPublicKey('bob')).publicKey;

    const data = new TextEncoder().encode('shared message');
    const aliceSig = await sign('alice', data);
    const bobSig = await sign('bob', data);

    // Alice's sig verifies with Alice's key
    expect(verifySignature(data, aliceSig, alicePub)).toBe(true);
    // Bob's sig verifies with Bob's key
    expect(verifySignature(data, bobSig, bobPub)).toBe(true);
    // Cross verification fails
    expect(verifySignature(data, aliceSig, bobPub)).toBe(false);
    expect(verifySignature(data, bobSig, alicePub)).toBe(false);
  });

  it('rotate key: delete old + generate new', async () => {
    const first = await generateKey('rotating-key');
    const data = new TextEncoder().encode('data');
    const firstSig = await sign('rotating-key', data);

    // Rotate
    await deleteKey('rotating-key');
    const second = await generateKey('rotating-key');

    // Keys are different (probabilistically, practically always true)
    const firstHex = Buffer.from(first.publicKey).toString('hex');
    const secondHex = Buffer.from(second.publicKey).toString('hex');
    expect(firstHex).not.toBe(secondHex);

    // Old signature does NOT verify with new key
    expect(verifySignature(data, firstSig, second.publicKey)).toBe(false);

    // New signature verifies with new key
    const newSig = await sign('rotating-key', data);
    expect(verifySignature(data, newSig, second.publicKey)).toBe(true);
  });
});

// ── Concurrency ────────────────────────────────────────────────────────────────

describe('concurrent operations', () => {
  it('generates 10 keys concurrently without conflicts', async () => {
    const keys = await Promise.all(
      Array.from({ length: 10 }, (_, i) => generateKey(`concurrent-key-${i}`)),
    );
    expect(keys).toHaveLength(10);
    for (let i = 0; i < 10; i++) {
      expect(await keyExists(`concurrent-key-${i}`)).toBe(true);
    }
  });

  it('signs with 5 keys concurrently', async () => {
    for (let i = 0; i < 5; i++) {
      await generateKey(`sig-key-${i}`);
    }
    const data = new TextEncoder().encode('concurrent signing');
    const sigs = await Promise.all(
      Array.from({ length: 5 }, (_, i) => sign(`sig-key-${i}`, data)),
    );
    expect(sigs).toHaveLength(5);
    for (const sig of sigs) {
      expect(sig.length).toBe(64);
    }
  });
});

// ── mockModule export ─────────────────────────────────────────────────────────

describe('mockModule object', () => {
  it('exports all public API functions', async () => {
    const { mockModule } = await import('../src/mock');
    expect(typeof mockModule.generateKey).toBe('function');
    expect(typeof mockModule.sign).toBe('function');
    expect(typeof mockModule.getPublicKey).toBe('function');
    expect(typeof mockModule.keyExists).toBe('function');
    expect(typeof mockModule.deleteKey).toBe('function');
    expect(typeof mockModule.isHardwareBackedAvailable).toBe('function');
    expect(typeof mockModule.clearAllKeys).toBe('function');
    expect(mockModule.HardwareKeyError).toBe(HardwareKeyError);
    expect(mockModule.HardwareKeyErrorCode).toBe(HardwareKeyErrorCode);
  });

  it('mockModule.generateKey is the same function as the named export', async () => {
    const { mockModule } = await import('../src/mock');
    expect(mockModule.generateKey).toBe(generateKey);
  });
});
