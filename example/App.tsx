import { useState } from 'react';
import {
  generateKey,
  sign,
  getPublicKey,
  keyExists,
  deleteKey,
  isHardwareBackedAvailable,
  HardwareKeyError,
} from 'expo-hardware-key';
import { Button, Platform, ScrollView, Text, View, StyleSheet } from 'react-native';

const KEY_ID = 'integration-test-key';

type Result = { name: string; pass: boolean; detail: string };

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function runTests(): Promise<Result[]> {
  const results: Result[] = [];

  function pass(name: string, detail = '') {
    results.push({ name, pass: true, detail });
  }
  function fail(name: string, detail: string) {
    results.push({ name, pass: false, detail });
  }

  // Clean slate
  await deleteKey(KEY_ID);

  // 1. isHardwareBackedAvailable
  try {
    const available = await isHardwareBackedAvailable();
    pass('isHardwareBackedAvailable', `${available}`);
  } catch (e: any) {
    fail('isHardwareBackedAvailable', e.message);
  }

  // 2. keyExists before generate
  try {
    const exists = await keyExists(KEY_ID);
    if (!exists) pass('keyExists (before generate)', 'false');
    else fail('keyExists (before generate)', 'expected false');
  } catch (e: any) {
    fail('keyExists (before generate)', e.message);
  }

  // 3. generateKey
  let publicKey: Uint8Array | null = null;
  let securityLevel = '';
  try {
    const info = await generateKey(KEY_ID);
    publicKey = info.publicKey;
    securityLevel = info.securityLevel;
    if (info.publicKey.length === 33 && info.algorithm === 'P-256') {
      pass('generateKey', `securityLevel: ${securityLevel}`);
    } else {
      fail('generateKey', `unexpected: len=${info.publicKey.length} alg=${info.algorithm}`);
    }
  } catch (e: any) {
    fail('generateKey', e.message);
  }

  // 4. generateKey duplicate
  try {
    await generateKey(KEY_ID);
    fail('generateKey (duplicate)', 'did not throw');
  } catch (e: any) {
    if (e instanceof HardwareKeyError && e.code === 'KEY_ALREADY_EXISTS') {
      pass('generateKey (duplicate)', 'KEY_ALREADY_EXISTS');
    } else {
      fail('generateKey (duplicate)', `wrong error: ${e.code ?? e.message}`);
    }
  }

  // 5. keyExists after generate
  try {
    const exists = await keyExists(KEY_ID);
    if (exists) pass('keyExists (after generate)', 'true');
    else fail('keyExists (after generate)', 'expected true');
  } catch (e: any) {
    fail('keyExists (after generate)', e.message);
  }

  // 6. getPublicKey matches generateKey
  try {
    const info = await getPublicKey(KEY_ID);
    if (publicKey && arraysEqual(info.publicKey, publicKey)) {
      pass('getPublicKey', 'matches generateKey');
    } else {
      fail('getPublicKey', 'public key mismatch');
    }
  } catch (e: any) {
    fail('getPublicKey', e.message);
  }

  // 7. sign
  try {
    const data = new TextEncoder().encode('test payload');
    const sig = await sign(KEY_ID, data);
    if (sig.length === 64 && sig instanceof Uint8Array) {
      pass('sign', `${sig.length} bytes`);
    } else {
      fail('sign', `unexpected: len=${sig.length}`);
    }
  } catch (e: any) {
    fail('sign', e.message);
  }

  // 8. sign different data produces different signature
  try {
    const d1 = new TextEncoder().encode('data-1');
    const d2 = new TextEncoder().encode('data-2');
    const s1 = await sign(KEY_ID, d1);
    const s2 = await sign(KEY_ID, d2);
    if (!arraysEqual(s1, s2)) {
      pass('sign (different data)', 'signatures differ');
    } else {
      fail('sign (different data)', 'signatures identical');
    }
  } catch (e: any) {
    fail('sign (different data)', e.message);
  }

  // 9. deleteKey
  try {
    await deleteKey(KEY_ID);
    const exists = await keyExists(KEY_ID);
    if (!exists) pass('deleteKey', 'key gone');
    else fail('deleteKey', 'key still exists');
  } catch (e: any) {
    fail('deleteKey', e.message);
  }

  // 10. sign after delete
  try {
    await sign(KEY_ID, new Uint8Array(4));
    fail('sign (after delete)', 'did not throw');
  } catch (e: any) {
    if (e instanceof HardwareKeyError && e.code === 'KEY_NOT_FOUND') {
      pass('sign (after delete)', 'KEY_NOT_FOUND');
    } else {
      fail('sign (after delete)', `wrong error: ${e.code ?? e.message}`);
    }
  }

  // 11. getPublicKey after delete
  try {
    await getPublicKey(KEY_ID);
    fail('getPublicKey (after delete)', 'did not throw');
  } catch (e: any) {
    if (e instanceof HardwareKeyError && e.code === 'KEY_NOT_FOUND') {
      pass('getPublicKey (after delete)', 'KEY_NOT_FOUND');
    } else {
      fail('getPublicKey (after delete)', `wrong error: ${e.code ?? e.message}`);
    }
  }

  // 12. biometric key: generate with requireBiometrics
  const BIO_KEY = 'biometric-test-key';
  await deleteKey(BIO_KEY);
  try {
    const info = await generateKey(BIO_KEY, { requireBiometrics: true });
    if (info.publicKey.length === 33) {
      pass('generateKey (biometric)', `securityLevel: ${info.securityLevel}`);
    } else {
      fail('generateKey (biometric)', `unexpected key length: ${info.publicKey.length}`);
    }
  } catch (e: any) {
    fail('generateKey (biometric)', e.message);
  }

  // 13. sign with biometric key (should trigger Face ID / Touch ID)
  try {
    const data = new TextEncoder().encode('biometric test');
    const sig = await sign(BIO_KEY, data);
    if (sig.length === 64) {
      pass('sign (biometric)', `${sig.length} bytes — Face ID prompted`);
    } else {
      fail('sign (biometric)', `unexpected: len=${sig.length}`);
    }
  } catch (e: any) {
    if (e instanceof HardwareKeyError && e.code === 'BIOMETRIC_CANCELLED') {
      pass('sign (biometric)', 'BIOMETRIC_CANCELLED — prompt appeared, user dismissed');
    } else {
      fail('sign (biometric)', `${e.code ?? ''}: ${e.message}`);
    }
  }

  // 14. cleanup biometric key
  await deleteKey(BIO_KEY);

  // 15. deleteKey is no-op on missing key
  try {
    await deleteKey(KEY_ID);
    pass('deleteKey (no-op)', 'no throw');
  } catch (e: any) {
    fail('deleteKey (no-op)', e.message);
  }

  return results;
}

export default function App() {
  const [results, setResults] = useState<Result[] | null>(null);
  const [running, setRunning] = useState(false);

  const handleRun = async () => {
    setRunning(true);
    setResults(null);
    try {
      const r = await runTests();
      setResults(r);
    } catch (e: any) {
      setResults([{ name: 'FATAL', pass: false, detail: e.message }]);
    }
    setRunning(false);
  };

  const passed = results?.filter((r) => r.pass).length ?? 0;
  const total = results?.length ?? 0;

  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scroll}>
        <Text style={styles.header}>expo-hardware-key</Text>
        <Button title={running ? 'Running...' : 'Run Tests'} onPress={handleRun} disabled={running} />
        {results && (
          <Text style={[styles.summary, passed === total ? styles.green : styles.red]}>
            {passed}/{total} passed
          </Text>
        )}
        {results?.map((r, i) => (
          <View key={i} style={[styles.row, r.pass ? styles.passBg : styles.failBg]}>
            <Text style={styles.name}>{r.pass ? 'PASS' : 'FAIL'} {r.name}</Text>
            {r.detail ? <Text style={styles.detail}>{r.detail}</Text> : null}
          </View>
        ))}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#1a1a1a', paddingTop: Platform.OS === 'ios' ? 60 : 40 },
  scroll: { padding: 20 },
  header: { fontSize: 24, fontWeight: '700', color: '#fff', marginBottom: 16 },
  summary: { fontSize: 18, fontWeight: '600', marginTop: 12, marginBottom: 8 },
  green: { color: '#4ade80' },
  red: { color: '#f87171' },
  row: { padding: 12, borderRadius: 8, marginTop: 6 },
  passBg: { backgroundColor: '#14532d' },
  failBg: { backgroundColor: '#7f1d1d' },
  name: { color: '#fff', fontWeight: '600', fontSize: 14 },
  detail: { color: '#d4d4d4', fontSize: 12, marginTop: 2 },
});
